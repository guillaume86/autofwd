package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guillaume86/autofwd/internal/logx"
	"github.com/guillaume86/autofwd/internal/ports"
	"github.com/guillaume86/autofwd/internal/sshconn"
	"github.com/guillaume86/autofwd/internal/sshtest"
)

func echo(c net.Conn) {
	io.Copy(c, c)
	c.Close()
}

// harness wires a real sshconn.Dialer and Supervisor to an sshtest server.
type harness struct {
	t      *testing.T
	srv    *sshtest.Server
	logs   *sshtest.LogBuffer
	cancel context.CancelFunc
	done   chan error
}

type setupOpts struct {
	knownHosts func(*sshtest.Server) []string // default: the server's real key
	wrongKey   bool                           // client key the server does not accept
	tweak      func(*Options)
}

func setup(t *testing.T, so setupOpts) *harness {
	t.Helper()
	key, priv := sshtest.NewKey(t)
	srv := sshtest.Start(t, key.PublicKey())
	if so.wrongKey {
		_, priv = sshtest.NewKey(t)
	}
	knownHosts := so.knownHosts
	if knownHosts == nil {
		knownHosts = func(s *sshtest.Server) []string { return []string{s.KnownHostsLine()} }
	}
	cfgPath, _ := sshtest.WriteClientFiles(t, t.TempDir(), priv, knownHosts(srv), map[string]string{
		"dev": fmt.Sprintf("  HostName 127.0.0.1\n  Port %d\n  User tester", srv.Port),
	})

	logs := &sshtest.LogBuffer{}
	log := logx.New(logs, logx.Verbose)
	resolver, err := sshconn.NewResolver(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	dialer := sshconn.NewDialer(resolver, func(string) ([]byte, error) { return nil, errors.New("no prompts in tests") }, log)

	o := Options{
		Dest:       "dev",
		Dial:       DialFunc(dialer, "dev"),
		Filter:     ports.Filter{MinPort: 1024},
		Interval:   30 * time.Millisecond,
		BackoffMin: 20 * time.Millisecond,
		BackoffMax: 100 * time.Millisecond,
		Log:        log,
	}
	if so.tweak != nil {
		so.tweak(&o)
	}
	ctx, cancel := context.WithCancel(context.Background())
	h := &harness{t: t, srv: srv, logs: logs, cancel: cancel, done: make(chan error, 1)}
	go func() { h.done <- New(o).Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-h.done:
		case <-time.After(5 * time.Second):
			t.Error("supervisor did not stop")
		}
		if t.Failed() {
			t.Logf("logs:\n%s", logs)
		}
	})
	return h
}

func listening(addr string) bool {
	c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

// exchange writes msg and expects it echoed back on an open connection.
func exchange(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatalf("write: %v", err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

func dialExchange(t *testing.T, addr, msg string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	exchange(t, c, msg)
}

func hp(host string, port uint16) string { return net.JoinHostPort(host, fmt.Sprint(port)) }

func TestEndToEnd(t *testing.T) {
	if ProcCommand != sshtest.ProcCommand {
		t.Fatalf("test server answers %q, supervisor runs %q", sshtest.ProcCommand, ProcCommand)
	}
	h := setup(t, setupOpts{})
	pWild, pV6, pHalf := sshtest.FreePort(t), sshtest.FreePort(t), sshtest.FreePort(t)

	h.srv.Handle(hp("127.0.0.1", pWild), echo)
	h.srv.Handle(hp("::1", pV6), echo)
	h.srv.Handle(hp("127.0.0.1", pHalf), func(c net.Conn) {
		b, _ := io.ReadAll(c) // needs the client's half-close to arrive
		fmt.Fprintf(c, "read %d bytes", len(b))
		c.Close()
	})
	base := []sshtest.Row{
		{Local: hp("0.0.0.0", pWild), State: "0A"},
		{Local: hp("::1", pV6), State: "0A"},
		{Local: hp("127.0.0.1", pHalf), State: "0A"},
		{Local: "0.0.0.0:22", State: "0A"}, // below --min-port
		{Local: hp("127.0.0.1", pWild), Remote: "127.0.0.1:50000", State: "01"},
		{Local: "127.0.0.1:61000", Remote: "127.0.0.1:61001", State: "06"}, // TIME_WAIT
	}
	h.srv.SetProc(sshtest.ProcTables(base...))

	// Ports appear, on both loopbacks.
	sshtest.Eventually(t, 5*time.Second, "forwards to appear", func() bool {
		return listening(hp("127.0.0.1", pWild)) && listening(hp("127.0.0.1", pV6)) && listening(hp("127.0.0.1", pHalf))
	})
	dialExchange(t, hp("127.0.0.1", pWild), "hello over v4")
	dialExchange(t, hp("127.0.0.1", pV6), "remote ::1 target")
	if sshtest.HasIPv6Loopback() {
		dialExchange(t, hp("::1", pWild), "hello over v6")
	}
	dialed := strings.Join(h.srv.Dialed(), " ")
	for _, want := range []string{hp("127.0.0.1", pWild), hp("::1", pV6)} {
		if !strings.Contains(dialed, want) {
			t.Errorf("server never saw direct-tcpip to %s (saw %s)", want, dialed)
		}
	}
	for _, want := range []string{fmt.Sprintf("+ %d  http://localhost:%d\n", pWild, pWild), fmt.Sprintf("+ %d  http://localhost:%d  (remote ::1)", pV6, pV6)} {
		if !strings.Contains(h.logs.String(), want) {
			t.Errorf("logs lack %q", want)
		}
	}
	if strings.Contains(h.logs.String(), "+ 22 ") || strings.Contains(h.logs.String(), "+ 61000 ") {
		t.Error("forwarded a filtered or non-LISTEN port")
	}

	// Half-close travels end to end.
	c, err := net.Dial("tcp", hp("127.0.0.1", pHalf))
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, strings.Repeat("x", 100000))
	c.(*net.TCPConn).CloseWrite()
	reply, err := io.ReadAll(c)
	c.Close()
	if err != nil || string(reply) != "read 100000 bytes" {
		t.Fatalf("half-close reply %q, %v", reply, err)
	}

	// A port disappears: the listener goes, the in-flight connection stays.
	inflight, err := net.Dial("tcp", hp("127.0.0.1", pWild))
	if err != nil {
		t.Fatal(err)
	}
	defer inflight.Close()
	exchange(t, inflight, "before")
	h.srv.SetProc(sshtest.ProcTables(base[1:]...))
	sshtest.Eventually(t, 5*time.Second, "forward to disappear", func() bool { return !listening(hp("127.0.0.1", pWild)) })
	exchange(t, inflight, "still alive")
	if !strings.Contains(h.logs.String(), fmt.Sprintf("- %d\n", pWild)) {
		t.Errorf("logs lack '- %d'", pWild)
	}

	// A busy local port is reported and left alone.
	pBusy := sshtest.FreePort(t)
	squatter, err := net.Listen("tcp4", hp("127.0.0.1", pBusy))
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	h.srv.SetProc(sshtest.ProcTables(append(base[1:], sshtest.Row{Local: hp("0.0.0.0", pBusy), State: "0A"})...))
	sshtest.Eventually(t, 5*time.Second, "busy warning", func() bool {
		return strings.Contains(h.logs.String(), fmt.Sprintf("! %d local port busy", pBusy))
	})

	// The connection drops: forwards are torn down and come back.
	h.srv.KillConnections()
	sshtest.Eventually(t, 5*time.Second, "reconnect", func() bool {
		return strings.Count(h.logs.String(), " connected to dev") >= 2 && h.srv.Logins() >= 2
	})
	if !strings.Contains(h.logs.String(), "disconnected from dev:") {
		t.Error("no disconnect line logged")
	}
	sshtest.Eventually(t, 5*time.Second, "forwards after reconnect", func() bool { return listening(hp("127.0.0.1", pV6)) })
	dialExchange(t, hp("127.0.0.1", pV6), "after reconnect")
	inflight.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := inflight.Read(make([]byte, 1)); err == nil {
		t.Error("connection from the dead session was not closed")
	}

	// Shutdown closes every listener.
	h.cancel()
	select {
	case err := <-h.done:
		if err != nil {
			t.Fatalf("Run returned %v on cancel", err)
		}
		h.done <- nil // for Cleanup
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after cancel")
	}
	if listening(hp("127.0.0.1", pV6)) || listening(hp("127.0.0.1", pHalf)) {
		t.Error("listeners survived shutdown")
	}
}

func TestKeepaliveDetectsDeadPeer(t *testing.T) {
	h := setup(t, setupOpts{tweak: func(o *Options) {
		o.KeepaliveInterval = 50 * time.Millisecond
		o.KeepaliveTimeout = 150 * time.Millisecond
	}})
	p := sshtest.FreePort(t)
	h.srv.Handle(hp("127.0.0.1", p), echo)
	h.srv.SetProc(sshtest.ProcTables(sshtest.Row{Local: hp("127.0.0.1", p), State: "0A"}))
	sshtest.Eventually(t, 5*time.Second, "forward", func() bool { return listening(hp("127.0.0.1", p)) })

	h.srv.MuteKeepalives(true)
	sshtest.Eventually(t, 5*time.Second, "keepalive timeout", func() bool {
		return strings.Contains(h.logs.String(), "no keepalive reply within")
	})
	h.srv.MuteKeepalives(false)
	sshtest.Eventually(t, 5*time.Second, "reconnect", func() bool { return h.srv.Logins() >= 2 && listening(hp("127.0.0.1", p)) })
}

func runUntilError(t *testing.T, h *harness) error {
	t.Helper()
	select {
	case err := <-h.done:
		h.done <- err
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not fail")
		return nil
	}
}

func TestUnknownHostKeyIsFatal(t *testing.T) {
	h := setup(t, setupOpts{knownHosts: func(*sshtest.Server) []string { return nil }})
	err := runUntilError(t, h)
	var hke *sshconn.HostKeyError
	if !errors.As(err, &hke) || hke.Changed {
		t.Fatalf("want unknown-host error, got %v", err)
	}
	if !strings.Contains(err.Error(), "Run `ssh dev` once") {
		t.Errorf("message lacks advice: %v", err)
	}
	if h.srv.Logins() != 0 {
		t.Error("authenticated to an unverified host")
	}
}

func TestChangedHostKeyIsFatal(t *testing.T) {
	h := setup(t, setupOpts{knownHosts: func(s *sshtest.Server) []string {
		// Same host entry, someone else's key.
		impostor, _ := sshtest.NewKey(t)
		return []string{fmt.Sprintf("[127.0.0.1]:%d %s", s.Port, ssh.MarshalAuthorizedKey(impostor.PublicKey()))}
	}})
	err := runUntilError(t, h)
	var hke *sshconn.HostKeyError
	if !errors.As(err, &hke) || !hke.Changed {
		t.Fatalf("want changed-key error, got %v", err)
	}
	if !strings.Contains(err.Error(), "HOST KEY MISMATCH") {
		t.Errorf("message: %v", err)
	}
	if h.srv.Logins() != 0 {
		t.Error("authenticated to an unverified host")
	}
}

func TestAuthFailureIsFatalOnFirstConnect(t *testing.T) {
	h := setup(t, setupOpts{wrongKey: true})
	err := runUntilError(t, h)
	var ae *sshconn.AuthError
	if !errors.As(err, &ae) {
		t.Fatalf("want AuthError, got %v", err)
	}
}

func TestUnreachableHostIsRetried(t *testing.T) {
	h := setup(t, setupOpts{})
	h.srv.Close() // nothing listens any more
	sshtest.Eventually(t, 5*time.Second, "two failed attempts", func() bool {
		logs := h.logs.String()
		// The first failure is spelled out; identical repeats are collapsed.
		return strings.Count(logs, "! connect to dev failed") == 1 && strings.Contains(logs, "! still cannot connect to dev")
	})
	select {
	case err := <-h.done:
		t.Fatalf("Run gave up on a network error: %v", err)
	default:
	}
}
