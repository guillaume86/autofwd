package sshconn

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guillaume86/autofwd/internal/logx"
)

// Dialer connects to hosts. Keep one per process so decrypted keys are
// reused across reconnects.
type Dialer struct {
	resolver *Resolver
	keys     *keyRing
	log      *logx.Logger
	// HandshakeTimeout bounds TCP connect plus SSH handshake per hop, not
	// counting time spent typing a passphrase. Default 30s.
	HandshakeTimeout time.Duration
}

func NewDialer(r *Resolver, prompt PromptFunc, log *logx.Logger) *Dialer {
	if prompt == nil {
		prompt = TerminalPrompt
	}
	return &Dialer{
		resolver:         r,
		keys:             &keyRing{keys: make(map[string]*keyFile), prompt: prompt, log: log},
		log:              log,
		HandshakeTimeout: 30 * time.Second,
	}
}

// Conn is a connection to the destination, plus the jump hosts it runs over.
type Conn struct {
	*ssh.Client
	Host  Host
	jumps []*ssh.Client // outermost first
}

// Close closes the connection and every jump host behind it. The outermost
// hop, the one on a real socket, goes first: closing an inner client on a
// hung link would block writing its close message through the jump.
func (c *Conn) Close() error {
	for _, j := range c.jumps {
		j.Close()
	}
	return c.Client.Close()
}

// Resolve exposes the ssh_config lookup, mostly for logging.
func (d *Dialer) Resolve(dest string) (Host, error) { return d.resolver.Resolve(dest) }

// Dial connects to dest ("alias" or "user@alias").
func (d *Dialer) Dial(ctx context.Context, dest string) (*Conn, error) {
	h, err := d.resolver.Resolve(dest)
	if err != nil {
		return nil, err
	}
	return d.dialHost(ctx, h, 0)
}

const maxJumpDepth = 8

func (d *Dialer) dialHost(ctx context.Context, h Host, depth int) (*Conn, error) {
	if depth > maxJumpDepth {
		return nil, &ConfigError{fmt.Errorf("ProxyJump chain deeper than %d hops at %s (loop?)", maxJumpDepth, h.Alias)}
	}
	var jumps []*ssh.Client
	fail := func(err error) (*Conn, error) {
		for i := len(jumps) - 1; i >= 0; i-- {
			jumps[i].Close()
		}
		return nil, err
	}

	var via *ssh.Client
	if h.ProxyJump != "" {
		for i, hop := range strings.Split(h.ProxyJump, ",") {
			jh, err := d.resolveJump(strings.TrimSpace(hop))
			if err != nil {
				return fail(err)
			}
			if i == 0 {
				// The first hop follows its own config, ProxyJump included,
				// as ssh does.
				jc, err := d.dialHost(ctx, jh, depth+1)
				if err != nil {
					return fail(fmt.Errorf("jump host %s: %w", jh.Alias, err))
				}
				jumps = append(jumps, jc.jumps...)
				via = jc.Client
			} else {
				c, err := d.handshake(ctx, jh, via)
				if err != nil {
					return fail(fmt.Errorf("jump host %s: %w", jh.Alias, err))
				}
				via = c
			}
			jumps = append(jumps, via)
		}
	}
	c, err := d.handshake(ctx, h, via)
	if err != nil {
		return fail(err)
	}
	return &Conn{Client: c, Host: h, jumps: jumps}, nil
}

func (d *Dialer) resolveJump(hop string) (Host, error) {
	user, host, port, err := parseJump(hop)
	if err != nil || host == "" {
		return Host{}, &ConfigError{fmt.Errorf("invalid ProxyJump entry %q: %v", hop, err)}
	}
	h, err := d.resolver.Resolve(host)
	if err != nil {
		return h, err
	}
	if user != "" {
		h.User = user
	}
	if port != "" {
		h.Port = port
	}
	return h, nil
}

// handshake opens a TCP connection to h (directly or through via) and runs
// the SSH handshake on it.
func (d *Dialer) handshake(ctx context.Context, h Host, via *ssh.Client) (*ssh.Client, error) {
	addr := net.JoinHostPort(h.HostName, h.Port)
	timeout := d.HandshakeTimeout
	if h.ConnectTimeout > 0 {
		timeout = h.ConnectTimeout
	}

	dctx, cancel := context.WithTimeout(ctx, timeout)
	var conn net.Conn
	var err error
	if via == nil {
		conn, err = (&net.Dialer{KeepAlive: 30 * time.Second}).DialContext(dctx, "tcp", addr)
	} else {
		conn, err = via.DialContext(dctx, "tcp", addr)
	}
	cancel()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) {
			hint := ""
			if h.Alias == h.HostName {
				hint = " (not a Host in ~/.ssh/config either)"
			}
			return nil, fmt.Errorf("cannot resolve %s: %s%s", h.HostName, dnsErr.Err, hint)
		}
		return nil, fmt.Errorf("connecting to %s: %w", addr, err)
	}

	// Abort the handshake on timeout or cancellation by closing the
	// connection; this works for jump channels too, which lack deadlines.
	// The timer is suspended while the user types a passphrase.
	var (
		mu       sync.Mutex
		timedOut bool
	)
	timer := time.AfterFunc(timeout, func() {
		mu.Lock()
		timedOut = true
		mu.Unlock()
		conn.Close()
	})
	stopCancel := context.AfterFunc(ctx, func() { conn.Close() })
	defer stopCancel()
	pause := func() func() {
		timer.Stop()
		return func() { timer.Reset(timeout) }
	}

	keyAddr := h.knownHostsAddr()
	hostKeyCB, algos, err := hostKeyChecker(h, keyAddr)
	if err != nil {
		timer.Stop()
		conn.Close()
		return nil, err
	}
	signers, agentCloser := d.keys.signers(h, pause)
	defer agentCloser.Close()

	cfg := &ssh.ClientConfig{
		User:              h.User,
		Auth:              []ssh.AuthMethod{ssh.PublicKeysCallback(signers)},
		HostKeyCallback:   hostKeyCB,
		HostKeyAlgorithms: algos,
	}
	d.log.Debugf("  handshake with %s@%s (known host key types %v)", h.User, addr, algos)
	c, chans, reqs, err := ssh.NewClientConn(conn, keyAddr, cfg)
	timer.Stop()
	if err != nil {
		conn.Close()
		mu.Lock()
		to := timedOut
		mu.Unlock()
		var hke *HostKeyError
		var pe *PassphraseError
		switch {
		case errors.As(err, &hke):
			return nil, hke
		case ctx.Err() != nil:
			return nil, ctx.Err()
		case to:
			return nil, fmt.Errorf("ssh handshake with %s timed out after %v", addr, timeout)
		case errors.As(err, &pe):
			// The server accepted the key but it could not be decrypted;
			// retrying would only fail the same way without a prompt.
			return nil, &AuthError{Host: h.User + "@" + addr, Err: pe}
		case strings.Contains(err.Error(), "unable to authenticate"):
			return nil, &AuthError{Host: h.User + "@" + addr, Err: err}
		}
		return nil, fmt.Errorf("ssh handshake with %s: %w", addr, err)
	}
	return ssh.NewClient(c, chans, reqs), nil
}
