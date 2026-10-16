// Package supervisor keeps an SSH connection alive and, while it is up,
// mirrors the remote host's listening TCP ports onto local loopback.
package supervisor

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guillaume86/autofwd/internal/forward"
	"github.com/guillaume86/autofwd/internal/logx"
	"github.com/guillaume86/autofwd/internal/ports"
	"github.com/guillaume86/autofwd/internal/procnet"
	"github.com/guillaume86/autofwd/internal/sshconn"
)

// Client is what a live connection must offer. *sshconn.Conn implements it.
type Client interface {
	forward.Dialer
	NewSession() (*ssh.Session, error)
	SendRequest(name string, wantReply bool, payload []byte) (bool, []byte, error)
	Wait() error
	Close() error
}

// ProcCommand reads the kernel's TCP tables; plain cat works on any Linux,
// with or without iproute2.
const ProcCommand = "cat /proc/net/tcp /proc/net/tcp6"

type Options struct {
	Dest string // for log lines
	Dial func(ctx context.Context) (Client, error)

	Filter   ports.Filter
	Interval time.Duration // between polls; default 2s

	KeepaliveInterval time.Duration // default 30s
	KeepaliveTimeout  time.Duration // default 15s
	PollTimeout       time.Duration // default 15s
	BackoffMin        time.Duration // default 1s
	BackoffMax        time.Duration // default 30s

	Forward forward.Options
	Log     *logx.Logger
}

// ConnState is where the supervisor is in its connect/serve/retry cycle.
type ConnState int

const (
	Connecting ConnState = iota
	Connected
	Waiting // between attempts, reconnecting at Status.RetryAt
)

func (s ConnState) String() string {
	switch s {
	case Connecting:
		return "connecting"
	case Connected:
		return "connected"
	default:
		return "reconnecting"
	}
}

// Skipped is a remote listener the filter excluded.
type Skipped struct {
	Port   uint16
	Reason string
}

// Status is a snapshot for the interactive status view.
type Status struct {
	Dest          string
	State         ConnState
	Since         time.Time // when State began
	RetryAt       time.Time // next attempt, when State is Waiting
	LastError     string    // why the last attempt or connection ended
	LastKeepalive time.Time
	Interval      time.Duration
	Forwards      []forward.PortStatus
	Busy          []forward.BusyStatus
	Skipped       []Skipped
}

type Supervisor struct {
	o    Options
	poke chan struct{}

	mu sync.Mutex
	st Status
	m  *forward.Manager // the live connection's manager, nil between connections
}

// Status returns a snapshot of the current state.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := s.st
	st.Skipped = slices.Clone(st.Skipped)
	if s.m != nil {
		st.Forwards, st.Busy = s.m.Status()
	}
	return st
}

// Poke asks for an immediate poll and retries busy ports right away.
func (s *Supervisor) Poke() {
	s.mu.Lock()
	m := s.m
	s.mu.Unlock()
	if m != nil {
		m.RetryNow()
	}
	select {
	case s.poke <- struct{}{}:
	default:
	}
}

func (s *Supervisor) setState(f func(*Status)) {
	s.mu.Lock()
	f(&s.st)
	s.mu.Unlock()
}

func New(o Options) *Supervisor {
	def := func(d *time.Duration, v time.Duration) {
		if *d <= 0 {
			*d = v
		}
	}
	def(&o.Interval, 2*time.Second)
	def(&o.KeepaliveInterval, 30*time.Second)
	def(&o.KeepaliveTimeout, 15*time.Second)
	def(&o.PollTimeout, 15*time.Second)
	def(&o.BackoffMin, time.Second)
	def(&o.BackoffMax, 30*time.Second)
	if o.Forward.Log == nil {
		o.Forward.Log = o.Log
	}
	s := &Supervisor{o: o, poke: make(chan struct{}, 1)}
	s.st = Status{Dest: o.Dest, State: Connecting, Since: time.Now(), Interval: o.Interval}
	return s
}

// fatal reports errors that retrying cannot fix. Authentication failures are
// fatal only before the first successful connection: later on they are more
// likely a transiently unavailable agent.
func fatal(err error, everConnected bool) bool {
	var hke *sshconn.HostKeyError
	var ce *sshconn.ConfigError
	var ae *sshconn.AuthError
	return errors.As(err, &hke) || errors.As(err, &ce) || (!everConnected && errors.As(err, &ae))
}

// Run connects, forwards, and reconnects with exponential backoff until ctx
// is cancelled (returning nil) or a fatal error occurs.
func (s *Supervisor) Run(ctx context.Context) error {
	o := s.o
	backoff := o.BackoffMin
	everConnected := false
	wait := func() bool {
		t := time.NewTimer(backoff)
		defer t.Stop()
		backoff = min(backoff*2, o.BackoffMax)
		select {
		case <-ctx.Done():
			return false
		case <-t.C:
			return true
		}
	}

	var (
		lastErr   string    // collapses identical repeated connect failures
		downSince time.Time // when the last connection was lost
	)
	for {
		o.Log.Debugf("  connecting to %s", o.Dest)
		s.setState(func(st *Status) { st.State, st.Since = Connecting, time.Now() })
		client, err := o.Dial(ctx)
		if ctx.Err() != nil {
			if client != nil {
				client.Close()
			}
			return nil
		}
		if err != nil {
			if fatal(err, everConnected) {
				return err
			}
			if msg := err.Error(); msg == lastErr {
				o.Log.Warnf("! still cannot connect to %s (retry in %v)", o.Dest, backoff)
			} else {
				lastErr = msg
				o.Log.Warnf("! connect to %s failed: %v (retry in %v)", o.Dest, err, backoff)
			}
			s.setState(func(st *Status) {
				st.State, st.Since, st.RetryAt, st.LastError = Waiting, time.Now(), time.Now().Add(backoff), err.Error()
			})
			if !wait() {
				return nil
			}
			continue
		}

		everConnected = true
		lastErr = ""
		if downSince.IsZero() {
			o.Log.Statef("connected to %s", o.Dest)
		} else {
			o.Log.Statef("connected to %s (down %s)", o.Dest, time.Since(downSince).Round(time.Second))
		}
		started := time.Now()
		s.setState(func(st *Status) { st.State, st.Since, st.LastError = Connected, started, "" })
		err = s.serve(ctx, client)
		if ctx.Err() != nil {
			o.Log.Statef("disconnected from %s", o.Dest)
			return nil
		}
		downSince = time.Now()
		if time.Since(started) > o.BackoffMax {
			backoff = o.BackoffMin // it was a healthy connection
		}
		o.Log.Statef("disconnected from %s: %v (reconnect in %v)", o.Dest, err, backoff)
		s.setState(func(st *Status) {
			st.State, st.Since, st.RetryAt, st.LastError = Waiting, downSince, downSince.Add(backoff), err.Error()
		})
		if !wait() {
			return nil
		}
	}
}

// serve runs one connection's lifetime: discovery, forwarding and liveness
// checks. Whichever fails first tears everything down.
func (s *Supervisor) serve(parent context.Context, client Client) error {
	ctx, cancel := context.WithCancelCause(parent)
	defer cancel(nil)
	// Whatever ends this connection, close the transport at once. Nothing
	// else reliably unblocks goroutines stuck on a link that went silent
	// without closing (laptop sleep, dead VPN): session opens and closes
	// would otherwise wait for the peer forever.
	stop := context.AfterFunc(ctx, func() { client.Close() })
	defer stop()

	m := forward.New(client, s.o.Forward)
	s.mu.Lock()
	s.m = m
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		s.m = nil
		s.st.Skipped = nil
		s.mu.Unlock()
	}()

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		err := client.Wait()
		if err == nil || errors.Is(err, io.EOF) {
			err = errors.New("connection closed by remote")
		}
		cancel(err)
	}()
	go func() {
		defer wg.Done()
		if err := s.keepalive(ctx, client); err != nil {
			cancel(err)
		}
	}()

	if err := s.discover(ctx, client, m); err != nil {
		cancel(err)
	}
	// Transport first: a proxied write stuck behind a full buffer holds the
	// mux, and closing channels through it would block the manager.
	client.Close()
	m.Close()
	wg.Wait()
	return context.Cause(ctx)
}

func (s *Supervisor) keepalive(ctx context.Context, client Client) error {
	t := time.NewTicker(s.o.KeepaliveInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		}
		reply := make(chan error, 1)
		go func() {
			// OpenSSH answers with a failure reply; any reply proves life.
			_, _, err := client.SendRequest("keepalive@openssh.com", true, nil)
			reply <- err
		}()
		timer := time.NewTimer(s.o.KeepaliveTimeout)
		select {
		case err := <-reply:
			timer.Stop()
			if err != nil {
				return fmt.Errorf("keepalive: %w", err)
			}
			s.o.Log.Debugf("  keepalive ok")
			s.setState(func(st *Status) { st.LastKeepalive = time.Now() })
		case <-timer.C:
			return fmt.Errorf("no keepalive reply within %v", s.o.KeepaliveTimeout)
		case <-ctx.Done():
			timer.Stop()
			return nil
		}
	}
}

// discover polls the remote port tables and syncs the forward manager until
// ctx ends or polling keeps failing.
func (s *Supervisor) discover(ctx context.Context, client Client, m *forward.Manager) error {
	t := time.NewTicker(s.o.Interval)
	defer t.Stop()
	failures := 0
	var lastUnusable string
	for {
		ls, err := s.poll(ctx, client)
		switch {
		case ctx.Err() != nil:
			return nil
		case err != nil:
			failures++
			if failures >= 3 {
				return fmt.Errorf("port discovery: %w", err)
			}
			s.o.Log.Warnf("! port discovery: %v", err)
		default:
			failures = 0
			targets, unusable := ports.Select(ls, s.o.Filter)
			if u := fmt.Sprint(unusable); len(unusable) > 0 && u != lastUnusable {
				s.o.Log.Debugf("  not forwarding link-local listeners without a known scope: %v", unusable)
				lastUnusable = u
			}
			skipped := s.skipped(ls)
			s.setState(func(st *Status) { st.Skipped = skipped })
			m.Sync(targets)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
		case <-s.poke:
		}
	}
}

// skipped lists the remote listeners the filter excluded, one entry per
// port, sorted.
func (s *Supervisor) skipped(ls []procnet.Listener) []Skipped {
	seen := make(map[uint16]bool)
	var out []Skipped
	for _, l := range ls {
		if seen[l.Port] {
			continue
		}
		if reason := s.o.Filter.Reason(l.Port); reason != "" {
			seen[l.Port] = true
			out = append(out, Skipped{Port: l.Port, Reason: reason})
		}
	}
	slices.SortFunc(out, func(a, b Skipped) int { return cmp.Compare(a.Port, b.Port) })
	return out
}

func (s *Supervisor) poll(ctx context.Context, client Client) ([]procnet.Listener, error) {
	var stdout bytes.Buffer
	stderr := &limitedBuffer{max: 4096}

	// Opening the session and running the command both go under the timer:
	// neither has a timeout of its own, and on a silent link they never
	// return. After a timeout the goroutine is left to finish when the
	// transport is closed; its channels are buffered so it cannot leak.
	opened := make(chan *ssh.Session, 1)
	done := make(chan error, 1)
	go func() {
		sess, err := client.NewSession()
		if err != nil {
			done <- fmt.Errorf("opening session: %w", err)
			return
		}
		sess.Stdout, sess.Stderr = &stdout, stderr
		opened <- sess
		done <- sess.Run(ProcCommand)
	}()
	closeSession := func() {
		select {
		case sess := <-opened:
			sess.Close()
		default:
		}
	}
	timer := time.NewTimer(s.o.PollTimeout)
	defer timer.Stop()
	var err error
	select {
	case err = <-done:
		closeSession()
	case <-timer.C:
		closeSession()
		return nil, fmt.Errorf("%s timed out after %v", ProcCommand, s.o.PollTimeout)
	case <-ctx.Done():
		closeSession()
		return nil, ctx.Err()
	}

	out := stdout.Bytes()
	if !bytes.Contains(out, []byte("local_address")) {
		if err == nil {
			err = errors.New("no TCP table in output (is the remote host Linux?)")
		}
		return nil, fmt.Errorf("%s: %w: %s", ProcCommand, err, bytes.TrimSpace(stderr.b.Bytes()))
	}
	// A non-zero exit with a table present usually means /proc/net/tcp6 is
	// missing because IPv6 is disabled; the IPv4 table is still good.
	if err != nil {
		s.o.Log.Debugf("  %s: %v: %s", ProcCommand, err, bytes.TrimSpace(stderr.b.Bytes()))
	}
	ls, perr := procnet.Parse(out)
	if perr != nil {
		s.o.Log.Debugf("  ignored unparsable lines: %v", perr)
	}
	return ls, nil
}

type limitedBuffer struct {
	b   bytes.Buffer
	max int
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	if room := l.max - l.b.Len(); room > 0 {
		l.b.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// DialFunc adapts an sshconn.Dialer for Options.Dial.
func DialFunc(d *sshconn.Dialer, dest string) func(context.Context) (Client, error) {
	return func(ctx context.Context) (Client, error) {
		c, err := d.Dial(ctx, dest)
		if err != nil {
			return nil, err
		}
		return c, nil
	}
}

var _ Client = (*sshconn.Conn)(nil)
