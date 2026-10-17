package procinfo

import (
	"net/netip"
	"os"
	"strings"
	"testing"

	"github.com/guillaume86/autofwd/internal/procnet"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func listener(addr string, uid uint32, inode uint64) procnet.Listener {
	ap := netip.MustParseAddrPort(addr)
	return procnet.Listener{Addr: ap.Addr(), Port: ap.Port(), UID: uid, Inode: inode}
}

type want struct {
	pid       int
	name      string
	unit      string
	namesPort bool
	label     string
}

func check(t *testing.T, got map[uint64]Socket, home string, ino uint64, w want) {
	t.Helper()
	s, ok := got[ino]
	if !ok {
		t.Errorf("inode %d: no entry", ino)
		return
	}
	pid, name := 0, ""
	if s.Proc != nil {
		pid, name = s.Proc.PID, s.Proc.Name
	}
	if pid != w.pid || name != w.name || s.Unit != w.unit || s.NamesPort != w.namesPort {
		t.Errorf("inode %d: got pid %d %q unit %q namesPort %v, want pid %d %q unit %q namesPort %v",
			ino, pid, name, s.Unit, s.NamesPort, w.pid, w.name, w.unit, w.namesPort)
	}
	if l := s.Label(home); l != w.label {
		t.Errorf("inode %d: label %q, want %q", ino, l, w.label)
	}
}

// ubuntu.txt is a trimmed capture from an Ubuntu 24.04 desktop with
// iproute2, systemd and cgroup v2: the richest case.
func TestParseUbuntu(t *testing.T) {
	ls := []procnet.Listener{
		listener("127.0.0.1:39563", 1000, 24689), // herdr's bun, own process
		listener("0.0.0.0:36938", 1000, 18104),   // a user-run tailscaled
		listener("127.0.0.1:45747", 0, 19795),    // containerd
		listener("100.64.0.10:59041", 0, 19818),
		listener("0.0.0.0:22", 0, 11706),    // ssh.socket: socket activation, no process in that cgroup
		listener("127.0.0.1:631", 0, 16981), // cups
		listener("0.0.0.0:111", 0, 1356),    // rpcbind.socket
	}
	env, got := Parse(fixture(t, "ubuntu.txt"), ls)
	if env.UID != 1000 || env.Home != "/home/dev" || !env.OthersVisible || !env.Cgroups {
		t.Errorf("env = %+v", env)
	}
	if env.UserName(0) != "root" || env.UserName(1000) != "dev" || env.UserName(4242) != "uid 4242" {
		t.Errorf("user names: %q %q %q", env.UserName(0), env.UserName(1000), env.UserName(4242))
	}
	h := env.Home
	check(t, got, h, 24689, want{pid: 2167, name: "bun", unit: "session-2.scope", label: "bun  ~"})
	check(t, got, h, 18104, want{pid: 1387, name: "tailscaled", unit: "tailscaled-user.service", label: "tailscaled  ~"})
	check(t, got, h, 19795, want{pid: 1326, name: "containerd", unit: "containerd.service", label: "containerd"})
	check(t, got, h, 19818, want{pid: 1306, name: "tailscaled", unit: "tailscaled.service", label: "tailscaled"})
	check(t, got, h, 11706, want{unit: "ssh.socket", label: "ssh.socket"})
	check(t, got, h, 16981, want{pid: 1298, name: "cupsd", unit: "cups.service", label: "cupsd"})
	check(t, got, h, 1356, want{unit: "rpcbind.socket", label: "rpcbind.socket"})

	if p := got[18104].Proc; !strings.HasPrefix(p.Cmdline, "/usr/sbin/tailscaled --tun=userspace-networking ") {
		t.Errorf("cmdline = %q", p.Cmdline)
	}
}

// busybox.txt comes from Alpine without iproute2, run as an unprivileged
// user: no ss, so other users' sockets rely on the port heuristic.
func TestParseBusyBox(t *testing.T) {
	ls := []procnet.Listener{
		listener("0.0.0.0:3000", 1000, 278865), // `nc -lk -p 3000` as dev, cwd /tmp
		listener("0.0.0.0:8080", 0, 278870),    // `nc -lk -p 8080` as root
		listener("0.0.0.0:9999", 0, 278871),    // nothing names it
	}
	env, got := Parse(fixture(t, "busybox.txt"), ls)
	if env.UID != 1000 || env.Home != "/home/dev" || !env.OthersVisible || env.Cgroups {
		t.Errorf("env = %+v", env)
	}
	check(t, got, env.Home, 278865, want{pid: 9, name: "nc", namesPort: true, label: "nc  /tmp"})
	check(t, got, env.Home, 278870, want{pid: 10, name: "nc", namesPort: true, label: "nc"})
	check(t, got, env.Home, 278871, want{})
}

// alpine-iproute2.txt has ss, but containers have no systemd: every cgroup
// is "/", which must not group unrelated processes together.
func TestParseContainerCgroups(t *testing.T) {
	ls := []procnet.Listener{
		listener("0.0.0.0:3000", 1000, 250920),
		listener("0.0.0.0:8080", 0, 252932),
	}
	env, got := Parse(fixture(t, "alpine-iproute2.txt"), ls)
	if env.Cgroups {
		t.Error("cgroup:/ counted as socket cgroups")
	}
	check(t, got, env.Home, 250920, want{pid: 14, name: "nc", namesPort: true, label: "nc  /tmp"})
	check(t, got, env.Home, 252932, want{pid: 15, name: "nc", namesPort: true, label: "nc"})
}

func TestParseNothing(t *testing.T) {
	// A shell that prints a banner and has none of the tools: everything is
	// unknown, nothing panics.
	ls := []procnet.Listener{listener("0.0.0.0:3000", 1000, 7)}
	env, got := Parse([]byte("Welcome!\n@@autofwd id\n@@autofwd end\n"), ls)
	if env.UID != -1 || env.OthersVisible || env.Cgroups {
		t.Errorf("env = %+v", env)
	}
	if s := got[7]; s.Known() {
		t.Errorf("socket = %+v", s)
	}
	if env, got := Parse(nil, ls); env.UID != -1 || got[7].Known() {
		t.Errorf("Parse(nil) = %+v, %+v", env, got)
	}
}

func TestParseHidepid(t *testing.T) {
	// hidepid=2: only the user's own processes are listed, pid 1 is not.
	out := "@@autofwd id\n1000\n/home/u\n50\n" +
		"@@autofwd fd\n/proc/700/fd/:\nlrwx------ 1 u u 64 Oct 17 09:43 3 -> socket:[11]\n" +
		"@@autofwd stat\n700 (node) S 600 1 1\n" +
		"@@autofwd cmdline\n==> /dev/null <==\n\n==> /proc/700/cmdline <==\nnode\x00server.js\x00\n@@autofwd end\n"
	env, got := Parse([]byte(out), []procnet.Listener{listener("0.0.0.0:3000", 1000, 11)})
	if env.OthersVisible {
		t.Error("OthersVisible with pid 1 hidden")
	}
	if p := got[11].Proc; p == nil || p.Name != "node" || p.Cmdline != "node server.js" {
		t.Errorf("proc = %+v", p)
	}
}

func TestParseExcludesOwnScript(t *testing.T) {
	// grep's arguments hold inode numbers; one equal to a port must not
	// make grep look like that port's proxy.
	out := "@@autofwd id\n1000\n/home/u\n50\n" +
		"@@autofwd stat\n1 (init) S 0 1 1\n50 (sh) S 49 1 1\n51 (grep) S 50 1 1\n" +
		"@@autofwd cmdline\n==> /dev/null <==\n\n==> /proc/1/cmdline <==\n/sbin/init\x00\n" +
		"==> /proc/51/cmdline <==\ngrep\x00-F\x00-e\x00socket:[5000]\x00\n@@autofwd end\n"
	_, got := Parse([]byte(out), []procnet.Listener{listener("0.0.0.0:5000", 0, 5000)})
	if got[5000].Known() {
		t.Errorf("attributed to the script: %+v", got[5000].Proc)
	}
}

func TestTopmostHolder(t *testing.T) {
	// A pre-fork server: the parent and its workers all hold the socket.
	out := "@@autofwd id\n1000\n/home/u\n" +
		"@@autofwd fd\n/proc/300/fd/:\nl 3 -> socket:[9]\n/proc/301/fd/:\nl 3 -> socket:[9]\n/proc/200/fd/:\nl 3 -> socket:[9]\n" +
		"@@autofwd stat\n200 (gunicorn: worker) S 100 1 1\n300 (gunicorn: worker) S 100 1 1\n100 (gunicorn) S 1 1 1\n301 (x) S 300 1 1\n" +
		"@@autofwd end\n"
	// 100 does not hold it here; 200 and 300 are siblings, 301 is 300's child.
	_, got := Parse([]byte(out), []procnet.Listener{listener("0.0.0.0:8000", 1000, 9)})
	if p := got[9].Proc; p == nil || p.PID != 200 || p.Name != "gunicorn: worker" {
		t.Errorf("proc = %+v", p)
	}
}

func TestDeepestMatch(t *testing.T) {
	// docker-proxy style: a wrapper and its child both name the port.
	out := "@@autofwd id\n1000\n/home/u\n" +
		"@@autofwd stat\n10 (wrap) S 1 1 1\n11 (docker-proxy) S 10 1 1\n" +
		"@@autofwd cmdline\n==> /proc/10/cmdline <==\nwrap\x00--port\x005432\x00\n" +
		"==> /proc/11/cmdline <==\ndocker-proxy\x00-host-port\x005432\x00\n@@autofwd end\n"
	_, got := Parse([]byte(out), []procnet.Listener{listener("0.0.0.0:5432", 0, 3)})
	if p := got[3].Proc; p == nil || p.PID != 11 || !got[3].NamesPort {
		t.Errorf("socket = %+v proc %+v", got[3], p)
	}
}

func TestMentionsPort(t *testing.T) {
	for _, tt := range []struct {
		cmd  string
		port uint16
		want bool
	}{
		{"docker-proxy -host-port 5432", 5432, true},
		{"serve --port=3000", 3000, true},
		{"serve :8080", 80, false},
		{"serve 8080", 8080, true},
		{"serve 18080 8080x", 8080, true},
		{"serve 18080", 8080, false},
		{"", 80, false},
	} {
		if got := mentionsPort(tt.cmd, tt.port); got != tt.want {
			t.Errorf("mentionsPort(%q, %d) = %v", tt.cmd, tt.port, got)
		}
	}
}

func TestTilde(t *testing.T) {
	for _, tt := range [][3]string{
		{"/home/u", "/home/u", "~"},
		{"/home/u/src/app", "/home/u", "~/src/app"},
		{"/home/user2", "/home/u", "/home/user2"},
		{"/srv", "", "/srv"},
		{"/srv", "/", "/srv"},
	} {
		if got := tilde(tt[0], tt[1]); got != tt[2] {
			t.Errorf("tilde(%q, %q) = %q, want %q", tt[0], tt[1], got, tt[2])
		}
	}
}

func TestScript(t *testing.T) {
	s := Script([]uint64{24689, 18104})
	for _, want := range []string{"-e 'socket:[24689]' -e 'socket:[18104]'", "LC_ALL=C", "@@autofwd end"} {
		if !strings.Contains(s, want) {
			t.Errorf("script lacks %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "\r") {
		t.Error("script has CR characters")
	}
}
