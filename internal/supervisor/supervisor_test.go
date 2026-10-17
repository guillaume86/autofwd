package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"regexp"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/guillaume86/autofwd/internal/logx"
	"github.com/guillaume86/autofwd/internal/ports"
	"github.com/guillaume86/autofwd/internal/procinfo"
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
	sup    *Supervisor
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
	h := &harness{t: t, srv: srv, sup: New(o), logs: logs, cancel: cancel, done: make(chan error, 1)}
	go func() { h.done <- h.sup.Run(ctx) }()
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

// procInfoOutput fakes the lookup script's output for TestProcessRules.
// containerd's root-owned socket is attributed through its cgroup, the
// Docker one through the port in docker-proxy's command line.
func procInfoOutput(pContainerd, pDocker uint16) string {
	return "@@autofwd id\n1000\n/home/tester\n" +
		fmt.Sprintf("@@autofwd ss\nLISTEN 0 4096 127.0.0.1:%d 0.0.0.0:* ino:13 sk:1 cgroup:/system.slice/containerd.service <->\n", pContainerd) +
		"@@autofwd cgroup\n==> /dev/null <==\n\n==> /proc/300/cgroup <==\n0::/system.slice/containerd.service\n\n" +
		"==> /proc/301/cgroup <==\n0::/system.slice/docker.service\n" +
		"@@autofwd passwd\nroot:0\ntester:1000\n" +
		"@@autofwd fd\n/proc/200/fd/:\nl 3 -> socket:[11]\n/proc/201/fd/:\nl 3 -> socket:[12]\n/proc/202/fd/:\nl 3 -> socket:[15]\n" +
		"@@autofwd cwd\nl /proc/200/cwd -> /home/tester/app\nl /proc/201/cwd -> /home/tester\nl /proc/202/cwd -> /srv\n" +
		"@@autofwd stat\n1 (init) S 0\n200 (node) S 1\n201 (tailscaled) S 1\n202 (python3) S 1\n300 (containerd) S 1\n301 (docker-proxy) S 1\n" +
		"@@autofwd cmdline\n==> /dev/null <==\n\n" +
		"==> /proc/1/cmdline <==\n/sbin/init\x00\n" +
		"==> /proc/200/cmdline <==\nnode\x00server.js\x00\n" +
		"==> /proc/201/cmdline <==\n/usr/sbin/tailscaled\x00--tun=userspace-networking\x00\n" +
		"==> /proc/202/cmdline <==\npython3\x00-m\x00http.server\x00\n" +
		"==> /proc/300/cmdline <==\n/usr/bin/containerd\x00\n" +
		fmt.Sprintf("==> /proc/301/cmdline <==\n/usr/bin/docker-proxy\x00-host-port\x00%d\x00\n", pDocker) +
		"@@autofwd end\n"
}

func TestProcessRules(t *testing.T) {
	if procinfo.Command != sshtest.ProcInfoCommand {
		t.Fatalf("test server answers %q, supervisor runs %q", sshtest.ProcInfoCommand, procinfo.Command)
	}
	var ignore []*regexp.Regexp
	for _, s := range ports.DefaultIgnoreProcess {
		ignore = append(ignore, regexp.MustCompile(s))
	}
	h := setup(t, setupOpts{tweak: func(o *Options) { o.Filter.IgnoreProcess = ignore }})
	pNode, pTail, pContainerd, pDocker, pLater := sshtest.FreePort(t), sshtest.FreePort(t), sshtest.FreePort(t), sshtest.FreePort(t), sshtest.FreePort(t)
	var mu sync.Mutex
	var scripts []string
	h.srv.SetProcInfo(func(script string) string {
		mu.Lock()
		scripts = append(scripts, script)
		mu.Unlock()
		return procInfoOutput(pContainerd, pDocker)
	})
	h.srv.Handle(hp("127.0.0.1", pNode), echo)
	h.srv.Handle(hp("127.0.0.1", pDocker), echo)
	rows := []sshtest.Row{
		{Local: hp("0.0.0.0", pNode), State: "0A", Inode: 11},
		{Local: hp("0.0.0.0", pTail), State: "0A", Inode: 12},
		{Local: hp("127.0.0.1", pContainerd), State: "0A", Inode: 13, UID: sshtest.UID(0)},
		{Local: hp("0.0.0.0", pDocker), State: "0A", Inode: 14, UID: sshtest.UID(0)},
		{Local: "0.0.0.0:22", State: "0A", Inode: 16, UID: sshtest.UID(0)}, // below --min-port: never looked up
	}
	h.srv.SetProc(sshtest.ProcTables(rows...))

	sshtest.Eventually(t, 5*time.Second, "forwards to appear", func() bool {
		return listening(hp("127.0.0.1", pNode)) && listening(hp("127.0.0.1", pDocker))
	})
	dialExchange(t, hp("127.0.0.1", pDocker), "published by docker")
	for _, want := range []string{
		fmt.Sprintf("+ %d  http://localhost:%d  node  ~/app\n", pNode, pNode),
		fmt.Sprintf("+ %d  http://localhost:%d  docker-proxy\n", pDocker, pDocker),
		"process info: uid 1000, other users' processes visible, socket cgroups from ss",
		fmt.Sprintf("not forwarding %d tailscaled: in --ignore-process", pTail),
		fmt.Sprintf("not forwarding %d containerd: owned by root", pContainerd),
	} {
		if !strings.Contains(h.logs.String(), want) {
			t.Errorf("logs lack %q", want)
		}
	}
	if listening(hp("127.0.0.1", pTail)) || listening(hp("127.0.0.1", pContainerd)) {
		t.Error("forwarded an excluded port")
	}
	st := h.sup.Status()
	want := []Skipped{{Port: 22, Reason: "below --min-port 1024"}, {Port: pTail, Reason: "in --ignore-process", Process: "tailscaled"}, {Port: pContainerd, Reason: "owned by root", Process: "containerd"}}
	slices.SortFunc(want, func(a, b Skipped) int { return int(a.Port) - int(b.Port) })
	if !slices.Equal(st.Skipped, want) {
		t.Errorf("skipped = %+v\nwant      %+v", st.Skipped, want)
	}
	for _, f := range st.Forwards {
		if f.Port == pNode && f.Label != "node  ~/app" {
			t.Errorf("status label %q", f.Label)
		}
	}

	// Known sockets are not looked up again on later polls.
	n := h.srv.Lookups()
	time.Sleep(10 * 30 * time.Millisecond) // ten polls
	if got := h.srv.Lookups(); got != n {
		t.Errorf("%d lookups for unchanged sockets", got-n)
	}
	mu.Lock()
	if len(scripts) == 0 || strings.Contains(scripts[0], "socket:[16]") || !strings.Contains(scripts[0], "socket:[11]") {
		t.Errorf("first lookup asked for the wrong inodes:\n%s", scripts[0])
	}
	mu.Unlock()

	// A new socket triggers one lookup, for that socket only.
	h.srv.Handle(hp("127.0.0.1", pLater), echo)
	h.srv.SetProc(sshtest.ProcTables(append(rows, sshtest.Row{Local: hp("0.0.0.0", pLater), State: "0A", Inode: 15})...))
	sshtest.Eventually(t, 5*time.Second, "new forward", func() bool { return listening(hp("127.0.0.1", pLater)) })
	if !strings.Contains(h.logs.String(), fmt.Sprintf("+ %d  http://localhost:%d  python3  /srv\n", pLater, pLater)) {
		t.Error("new port not labeled")
	}
	mu.Lock()
	last := scripts[len(scripts)-1]
	mu.Unlock()
	if !strings.Contains(last, "socket:[15]") || strings.Contains(last, "socket:[11]") {
		t.Errorf("second lookup asked for the wrong inodes:\n%s", last)
	}
}

func TestProcessRulesNeedVisibility(t *testing.T) {
	// hidepid: other users' processes are invisible, so a Docker port could
	// not be recognized. Root's sockets are then forwarded, as before.
	h := setup(t, setupOpts{})
	pRoot := sshtest.FreePort(t)
	h.srv.SetProcInfo(func(string) string { return "@@autofwd id\n1000\n/home/tester\n@@autofwd end\n" })
	h.srv.SetProc(sshtest.ProcTables(sshtest.Row{Local: hp("0.0.0.0", pRoot), State: "0A", UID: sshtest.UID(0)}))
	sshtest.Eventually(t, 5*time.Second, "forward", func() bool { return listening(hp("127.0.0.1", pRoot)) })
	if !strings.Contains(h.logs.String(), "other users' processes hidden") {
		t.Error("detection not logged")
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
	sshtest.Eventually(t, 5*time.Second, "repeated failed attempts", func() bool {
		return strings.Contains(h.logs.String(), "! still cannot connect to dev")
	})
	// Each distinct error is spelled out once; identical repeats collapse to
	// "still cannot connect". The first attempt may race the server shutting
	// down and fail differently from the later "refused" ones, so more than
	// one spelled-out line is fine as long as none repeats.
	seen := map[string]bool{}
	for _, line := range strings.Split(h.logs.String(), "\n") {
		_, msg, ok := strings.Cut(line, "! connect to dev failed: ")
		if !ok {
			continue
		}
		msg, _, _ = strings.Cut(msg, " (retry in ")
		if seen[msg] {
			t.Errorf("error spelled out twice instead of collapsed: %s", msg)
		}
		seen[msg] = true
	}
	if len(seen) == 0 {
		t.Error("no spelled-out connect failure")
	}
	select {
	case err := <-h.done:
		t.Fatalf("Run gave up on a network error: %v", err)
	default:
	}
}
