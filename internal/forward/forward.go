// Package forward owns the local loopback listeners and pipes each accepted
// connection through the SSH client to the remote target.
package forward

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/guillaume86/autofwd/internal/logx"
)

// Dialer opens connections on the remote side. *ssh.Client implements it.
type Dialer interface {
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

// Options tunes a Manager. Zero values pick the defaults.
type Options struct {
	Log *logx.Logger
	// DialTimeout bounds each remote dial. Default 15s.
	DialTimeout time.Duration
	// RetryBusy is how long a port that could not be bound locally waits
	// before it is tried again while it stays up remotely. Default 30s.
	RetryBusy time.Duration
	// Now is the clock, replaceable in tests.
	Now func() time.Time
}

// Manager reconciles local listeners against the set of remote ports. It is
// tied to one SSH connection: create a new one after reconnecting.
type Manager struct {
	dialer Dialer
	opts   Options
	log    *logx.Logger
	ctx    context.Context // cancelled by Close; aborts pending dials
	cancel context.CancelFunc

	mu     sync.Mutex
	closed bool
	ports  map[uint16]*port
	failed map[uint16]failure
	conns  map[*proxyConn]struct{}
	wg     sync.WaitGroup // accept loops and proxied connections
}

type port struct {
	num       uint16
	target    atomic.Pointer[netip.AddrPort]
	listeners []net.Listener
	since     time.Time
	conns     atomic.Int32 // proxied connections currently open
	lastWarn  atomic.Int64 // unix nanos of the last dial-failure warning
}

// failure records a port that could not be bound locally.
type failure struct {
	reason  string
	retryAt time.Time
}

// PortStatus describes one active forward.
type PortStatus struct {
	Port   uint16
	Target netip.AddrPort // dialed on the remote side
	Since  time.Time
	Conns  int
}

// BusyStatus describes a port that is listening remotely but could not be
// bound locally.
type BusyStatus struct {
	Port    uint16
	Reason  string
	RetryAt time.Time
}

// LocalURL is the address users open in a browser for a forwarded port.
func LocalURL(port uint16) string { return "http://localhost:" + strconv.Itoa(int(port)) }

// loopback4 is the remote target that needs no mention in log lines.
var loopback4 = netip.MustParseAddr("127.0.0.1")

// describe renders the "+ port" line: the clickable local URL, and the
// remote target only when it is not the usual 127.0.0.1.
func describe(num uint16, target netip.AddrPort) string {
	s := fmt.Sprintf("+ %d  %s", num, LocalURL(num))
	if target.Addr() != loopback4 {
		s += fmt.Sprintf("  (remote %s)", target.Addr())
	}
	return s
}

func New(d Dialer, opts Options) *Manager {
	if opts.DialTimeout <= 0 {
		opts.DialTimeout = 15 * time.Second
	}
	if opts.RetryBusy <= 0 {
		opts.RetryBusy = 30 * time.Second
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	ctx, cancel := context.WithCancel(context.Background())
	return &Manager{
		dialer: d,
		opts:   opts,
		log:    opts.Log,
		ctx:    ctx,
		cancel: cancel,
		ports:  make(map[uint16]*port),
		failed: make(map[uint16]failure),
		conns:  make(map[*proxyConn]struct{}),
	}
}

// Status reports the active forwards and the busy ports, both sorted.
func (m *Manager) Status() ([]PortStatus, []BusyStatus) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var ps []PortStatus
	for _, num := range slices.Sorted(maps.Keys(m.ports)) {
		p := m.ports[num]
		ps = append(ps, PortStatus{Port: num, Target: *p.target.Load(), Since: p.since, Conns: int(p.conns.Load())})
	}
	var bs []BusyStatus
	for _, num := range slices.Sorted(maps.Keys(m.failed)) {
		f := m.failed[num]
		bs = append(bs, BusyStatus{Port: num, Reason: f.reason, RetryAt: f.retryAt})
	}
	return ps, bs
}

// RetryNow makes the next Sync try every busy port again, without waiting
// for the retry delay.
func (m *Manager) RetryNow() {
	m.mu.Lock()
	defer m.mu.Unlock()
	for num, f := range m.failed {
		f.retryAt = time.Time{}
		m.failed[num] = f
	}
}

// Sync makes the local listeners match desired, a map of port to the remote
// address to dial. Removed ports stop listening at once, but connections
// already accepted on them run to completion.
func (m *Manager) Sync(desired map[uint16]netip.AddrPort) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed {
		return
	}

	for _, num := range slices.Sorted(maps.Keys(m.ports)) {
		if _, ok := desired[num]; !ok {
			m.ports[num].close()
			delete(m.ports, num)
			m.log.Infof("- %d", num)
		}
	}
	// A port that went away remotely gets a fresh attempt when it returns.
	for num := range m.failed {
		if _, ok := desired[num]; !ok {
			delete(m.failed, num)
		}
	}

	now := m.opts.Now()
	for _, num := range slices.Sorted(maps.Keys(desired)) {
		target := desired[num]
		if p, ok := m.ports[num]; ok {
			if old := p.target.Swap(&target); *old != target {
				m.log.Infof("~ %d  remote listener moved to %s", num, target)
			}
			continue
		}
		prev, failedBefore := m.failed[num]
		if failedBefore && now.Before(prev.retryAt) {
			continue
		}
		p, err := m.open(num, target)
		if err != nil {
			m.failed[num] = failure{reason: err.Error(), retryAt: now.Add(m.opts.RetryBusy)}
			if failedBefore {
				m.log.Debugf("! %d %v (still; retry in %v)", num, err, m.opts.RetryBusy)
			} else {
				m.log.Warnf("! %d %v (retry in %v)", num, err, m.opts.RetryBusy)
			}
			continue
		}
		delete(m.failed, num)
		p.since = now
		m.ports[num] = p
		m.log.Infof("%s", describe(num, target))
	}
}

// Ports returns the ports currently listening locally, in order.
func (m *Manager) Ports() []uint16 {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.Sorted(maps.Keys(m.ports))
}

// Close stops every listener, aborts every proxied connection and waits for
// all goroutines to exit. Use it when the SSH connection is gone or the
// program is shutting down.
func (m *Manager) Close() {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		nums := slices.Sorted(maps.Keys(m.ports))
		for _, num := range nums {
			m.ports[num].close()
		}
		if len(nums) > 0 {
			// One line for the whole teardown, not one per port.
			m.log.Infof("- %s", strings.Trim(fmt.Sprint(nums), "[]"))
		}
		clear(m.ports)
		for pc := range m.conns {
			pc.abort()
		}
	}
	m.mu.Unlock()
	m.cancel()
	m.wg.Wait()
}

// busyError is a port something else already holds, with the reason.
type busyError struct{ reason string }

func (e busyError) Error() string { return "local port busy: " + e.reason }

// IsBusy reports whether err means the local port was taken rather than
// that binding failed for another reason.
func IsBusy(err error) bool {
	var be busyError
	return errors.As(err, &be)
}

type listenError struct{ err error }

func (e listenError) Error() string { return "cannot listen locally: " + e.err.Error() }
func (e listenError) Unwrap() error { return e.err }

// open binds 127.0.0.1:num and [::1]:num and starts accepting. It is called
// with m.mu held.
func (m *Manager) open(num uint16, target netip.AddrPort) (*port, error) {
	ps := strconv.Itoa(int(num))
	// Windows, and BSDs with SO_REUSEADDR, let a loopback bind coexist with
	// another process's wildcard listener, silently shadowing it. Probe first
	// so a local service on that port is never hijacked.
	if listeningLocally(ps) {
		return nil, busyError{"another local process listens on it"}
	}
	l4, err := net.Listen("tcp4", net.JoinHostPort("127.0.0.1", ps))
	if err != nil {
		if reason := busyReason(err); reason != "" {
			return nil, busyError{reason}
		}
		return nil, listenError{err}
	}
	lns := []net.Listener{l4}
	l6, err := net.Listen("tcp6", net.JoinHostPort("::1", ps))
	switch {
	case err == nil:
		lns = append(lns, l6)
	case busyReason(err) != "":
		l4.Close()
		return nil, busyError{busyReason(err)}
	default:
		// Most likely no IPv6 loopback on this machine; IPv4 alone will do.
		m.log.Debugf("  %d IPv6 loopback unavailable: %v", num, err)
	}

	p := &port{num: num, listeners: lns}
	p.target.Store(&target)
	for _, ln := range lns {
		m.wg.Add(1)
		go m.accept(p, ln)
	}
	return p, nil
}

func listeningLocally(port string) bool {
	for _, host := range []string{"127.0.0.1", "::1"} {
		c, err := net.DialTimeout("tcp", net.JoinHostPort(host, port), 300*time.Millisecond)
		if err == nil {
			c.Close()
			return true
		}
	}
	return false
}

func (p *port) close() {
	for _, ln := range p.listeners {
		ln.Close()
	}
}

func (m *Manager) accept(p *port, ln net.Listener) {
	defer m.wg.Done()
	for {
		c, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			// Transient failures such as running out of file descriptors.
			m.log.Debugf("! %d accept: %v", p.num, err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		m.handle(p, *p.target.Load(), c)
	}
}

// proxyConn is one accepted connection and, once dialed, its remote half.
type proxyConn struct {
	mu      sync.Mutex
	local   net.Conn
	remote  net.Conn
	aborted bool
}

// setRemote records the remote half, or reports false if the connection was
// aborted while dialing.
func (pc *proxyConn) setRemote(c net.Conn) bool {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if pc.aborted {
		return false
	}
	pc.remote = c
	return true
}

func (pc *proxyConn) abort() {
	pc.mu.Lock()
	defer pc.mu.Unlock()
	pc.aborted = true
	pc.local.Close()
	if pc.remote != nil {
		pc.remote.Close()
	}
}

func (m *Manager) handle(p *port, target netip.AddrPort, local net.Conn) {
	num := p.num
	pc := &proxyConn{local: local}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		local.Close()
		return
	}
	m.conns[pc] = struct{}{}
	m.wg.Add(1)
	m.mu.Unlock()

	go func() {
		defer m.wg.Done()
		defer func() {
			m.mu.Lock()
			delete(m.conns, pc)
			m.mu.Unlock()
		}()

		ctx, cancel := context.WithTimeout(m.ctx, m.opts.DialTimeout)
		remote, err := m.dialer.DialContext(ctx, "tcp", target.String())
		cancel()
		if err != nil {
			local.Close()
			if m.ctx.Err() == nil {
				m.warnDial(p, target, err)
			}
			return
		}
		if !pc.setRemote(remote) {
			remote.Close()
			return
		}
		p.conns.Add(1)
		defer p.conns.Add(-1)
		m.log.Debugf("  %d open from %s", num, local.RemoteAddr())
		up, down := Join(local, remote)
		m.log.Debugf("  %d closed from %s (%d bytes up, %d down)", num, local.RemoteAddr(), up, down)
	}()
}

// dialWarnInterval limits how often a port that keeps refusing connections
// is reported; a browser retrying a dead dev server would otherwise flood
// the log.
const dialWarnInterval = 10 * time.Second

func (m *Manager) warnDial(p *port, target netip.AddrPort, err error) {
	now := m.opts.Now().UnixNano()
	last := p.lastWarn.Load()
	if now-last < int64(dialWarnInterval) {
		m.log.Debugf("! %d dial %s: %v", p.num, target, err)
		return
	}
	if p.lastWarn.CompareAndSwap(last, now) {
		m.log.Warnf("! %d dial %s: %v", p.num, target, err)
	}
}

type closeWriter interface{ CloseWrite() error }

// Join copies a<->b until both directions are done, then closes both. An EOF
// in one direction is passed on as a half-close when the destination
// supports it; anything else tears the whole connection down so the other
// goroutine cannot block forever. It returns the bytes sent a->b and b->a.
func Join(a, b net.Conn) (aToB, bToA int64) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); aToB = pipe(b, a) }()
	go func() { defer wg.Done(); bToA = pipe(a, b) }()
	wg.Wait()
	a.Close()
	b.Close()
	return aToB, bToA
}

func pipe(dst, src net.Conn) int64 {
	n, err := io.Copy(dst, src)
	if err == nil {
		if cw, ok := dst.(closeWriter); ok && cw.CloseWrite() == nil {
			return n
		}
	}
	dst.Close()
	src.Close()
	return n
}
