package forward

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/guillaume86/autofwd/internal/logx"
)

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// fakeRemote answers dials by running handler on one end of a net.Pipe,
// standing in for the SSH client.
type fakeRemote struct {
	mu      sync.Mutex
	handler func(net.Conn)
	dialed  []string
}

func (f *fakeRemote) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	f.mu.Lock()
	f.dialed = append(f.dialed, addr)
	h := f.handler
	f.mu.Unlock()
	if h == nil {
		return nil, fmt.Errorf("connection refused")
	}
	// A real loopback TCP pair, so CloseWrite behaves like an SSH channel's.
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	defer ln.Close()
	c, err := net.Dial("tcp4", ln.Addr().String())
	if err != nil {
		return nil, err
	}
	s, err := ln.Accept()
	if err != nil {
		c.Close()
		return nil, err
	}
	go h(s)
	return c, nil
}

func echo(c net.Conn) {
	io.Copy(c, c)
	c.Close()
}

func freePort(t *testing.T) uint16 {
	t.Helper()
	for range 20 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		if l6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", p)); err == nil {
			l6.Close()
			return uint16(p)
		} else if busyReason(err) == "" {
			return uint16(p) // no IPv6 loopback here
		}
	}
	t.Fatal("no free port")
	return 0
}

func target(p uint16) map[uint16]Target {
	return map[uint16]Target{p: {Addr: netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p)}}
}

func roundTrip(t *testing.T, addr, msg string) {
	t.Helper()
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.WriteString(c, msg); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(msg))
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("read from %s: %v", addr, err)
	}
	if string(buf) != msg {
		t.Fatalf("got %q, want %q", buf, msg)
	}
}

func hasIPv6Loopback() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	l.Close()
	return true
}

func TestForwardBothLoopbacks(t *testing.T) {
	remote := &fakeRemote{handler: echo}
	logs := &syncBuffer{}
	m := New(remote, Options{Log: logx.New(logs, logx.Verbose)})
	defer m.Close()

	p := freePort(t)
	m.Sync(target(p))
	roundTrip(t, fmt.Sprintf("127.0.0.1:%d", p), "hello v4")
	if hasIPv6Loopback() {
		roundTrip(t, fmt.Sprintf("[::1]:%d", p), "hello v6")
	}
	if !strings.Contains(logs.String(), fmt.Sprintf("+ %d  http://localhost:%d", p, p)) {
		t.Errorf("missing + line in logs:\n%s", logs)
	}
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if remote.dialed[0] != fmt.Sprintf("127.0.0.1:%d", p) {
		t.Errorf("dialed %v", remote.dialed)
	}
}

func TestHalfClose(t *testing.T) {
	// The remote reads until EOF, then answers with what it got and closes:
	// that only works if the client's CloseWrite reaches it.
	remote := &fakeRemote{handler: func(c net.Conn) {
		b, _ := io.ReadAll(c)
		fmt.Fprintf(c, "got %d bytes", len(b))
		c.Close()
	}}
	m := New(remote, Options{})
	defer m.Close()
	p := freePort(t)
	m.Sync(target(p))

	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(c, "0123456789")
	if err := c.(*net.TCPConn).CloseWrite(); err != nil {
		t.Fatal(err)
	}
	reply, err := io.ReadAll(c)
	if err != nil {
		t.Fatal(err)
	}
	if string(reply) != "got 10 bytes" {
		t.Errorf("reply = %q", reply)
	}
}

func TestRemovedPortKeepsInflightConnections(t *testing.T) {
	m := New(&fakeRemote{handler: echo}, Options{})
	defer m.Close()
	p := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	m.Sync(target(p))

	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 5)
	io.WriteString(c, "first")
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatal(err)
	}

	m.Sync(nil)
	if got := m.Ports(); len(got) != 0 {
		t.Fatalf("ports after removal = %v", got)
	}
	if c2, err := net.DialTimeout("tcp", addr, time.Second); err == nil {
		c2.Close()
		t.Fatal("new connection accepted after port removal")
	}

	io.WriteString(c, "after")
	if _, err := io.ReadFull(c, buf); err != nil || string(buf) != "after" {
		t.Fatalf("in-flight connection broke: %q, %v", buf, err)
	}
}

func TestBusyPortSkippedAndRetried(t *testing.T) {
	p := freePort(t)
	addr := fmt.Sprintf("127.0.0.1:%d", p)
	squatter, err := net.Listen("tcp4", addr)
	if err != nil {
		t.Fatal(err)
	}

	now := time.Unix(1000, 0)
	logs := &syncBuffer{}
	m := New(&fakeRemote{handler: echo}, Options{
		Log: logx.New(logs, logx.Normal),
		Now: func() time.Time { return now },
	})
	defer m.Close()

	m.Sync(target(p))
	if len(m.Ports()) != 0 {
		t.Fatal("busy port was forwarded")
	}
	if want := fmt.Sprintf("! %d local port busy", p); strings.Count(logs.String(), want) != 1 {
		t.Fatalf("want one %q line, logs:\n%s", want, logs)
	}

	// Freed locally, but the retry window has not passed.
	squatter.Close()
	now = now.Add(10 * time.Second)
	m.Sync(target(p))
	if len(m.Ports()) != 0 {
		t.Fatal("retried before the 30s window")
	}

	now = now.Add(21 * time.Second)
	m.Sync(target(p))
	if got := m.Ports(); len(got) != 1 {
		t.Fatalf("not retried after 30s: %v", got)
	}
	roundTrip(t, addr, "ok")
}

func TestBusyPortRetriedWhenRemoteReturns(t *testing.T) {
	p := freePort(t)
	squatter, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		t.Fatal(err)
	}
	m := New(&fakeRemote{handler: echo}, Options{})
	defer m.Close()

	m.Sync(target(p))
	squatter.Close()
	m.Sync(nil)       // remote port disappears...
	m.Sync(target(p)) // ...and comes back: retry immediately
	if got := m.Ports(); len(got) != 1 {
		t.Fatalf("ports = %v, want %d", got, p)
	}
}

func TestBusyOnIPv6OnlyIsDetected(t *testing.T) {
	if !hasIPv6Loopback() {
		t.Skip("no IPv6 loopback")
	}
	p := freePort(t)
	squatter, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", p))
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()
	m := New(&fakeRemote{handler: echo}, Options{})
	defer m.Close()
	m.Sync(target(p))
	if got := m.Ports(); len(got) != 0 {
		t.Fatalf("port held on ::1 by someone else was forwarded: %v", got)
	}
	// The IPv4 half must have been released again.
	l, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		t.Fatalf("127.0.0.1:%d leaked: %v", p, err)
	}
	l.Close()
}

func TestDescribe(t *testing.T) {
	for _, tt := range []struct {
		t    Target
		want string
	}{
		{Target{Addr: netip.MustParseAddrPort("127.0.0.1:3000")}, "+ 3000  http://localhost:3000"},
		{Target{Addr: netip.MustParseAddrPort("127.0.0.1:3000"), Label: "node  ~/app"}, "+ 3000  http://localhost:3000  node  ~/app"},
		{Target{Addr: netip.MustParseAddrPort("[::1]:3000"), Label: "vite"}, "+ 3000  http://localhost:3000  vite  (remote ::1)"},
	} {
		if got := describe(3000, tt.t); got != tt.want {
			t.Errorf("describe = %q, want %q", got, tt.want)
		}
	}
}

func TestLabelUpdatesInPlace(t *testing.T) {
	m := New(&fakeRemote{handler: echo}, Options{})
	defer m.Close()
	p := freePort(t)
	addr := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), p)
	m.Sync(map[uint16]Target{p: {Addr: addr}})
	m.Sync(map[uint16]Target{p: {Addr: addr, Label: "node"}})
	if ps, _ := m.Status(); len(ps) != 1 || ps[0].Label != "node" {
		t.Errorf("status = %+v", ps)
	}
}

func TestTargetChangeUpdatesInPlace(t *testing.T) {
	remote := &fakeRemote{handler: echo}
	m := New(remote, Options{})
	defer m.Close()
	p := freePort(t)
	m.Sync(target(p))
	m.Sync(map[uint16]Target{p: {Addr: netip.AddrPortFrom(netip.IPv6Loopback(), p)}})
	roundTrip(t, fmt.Sprintf("127.0.0.1:%d", p), "x")
	remote.mu.Lock()
	defer remote.mu.Unlock()
	if got, want := remote.dialed[len(remote.dialed)-1], fmt.Sprintf("[::1]:%d", p); got != want {
		t.Errorf("dialed %s, want %s", got, want)
	}
}

func TestDialFailureClosesLocal(t *testing.T) {
	m := New(&fakeRemote{}, Options{})
	defer m.Close()
	p := freePort(t)
	m.Sync(target(p))
	c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("expected the local connection to be closed")
	}
}

func TestCloseAbortsEverythingWithoutLeaks(t *testing.T) {
	before := runtime.NumGoroutine()

	m := New(&fakeRemote{handler: echo}, Options{})
	p1, p2 := freePort(t), freePort(t)
	m.Sync(map[uint16]Target{
		p1: {Addr: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", p1))},
		p2: {Addr: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", p2))},
	})
	var conns []net.Conn
	for _, p := range []uint16{p1, p2, p1} {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", p))
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		io.WriteString(c, "x")
		c.SetDeadline(time.Now().Add(5 * time.Second))
		io.ReadFull(c, make([]byte, 1))
		conns = append(conns, c)
	}

	done := make(chan struct{})
	go func() { m.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Close hung")
	}
	for _, c := range conns {
		if _, err := c.Read(make([]byte, 1)); err == nil {
			t.Error("connection still open after Close")
		}
		c.Close()
	}
	m.Sync(target(p1)) // no-op after Close
	if len(m.Ports()) != 0 {
		t.Error("Sync after Close opened a port")
	}

	deadline := time.Now().Add(2 * time.Second)
	for runtime.NumGoroutine() > before && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := runtime.NumGoroutine(); n > before {
		buf := make([]byte, 1<<16)
		t.Errorf("goroutines: %d before, %d after\n%s", before, n, buf[:runtime.Stack(buf, true)])
	}
}
