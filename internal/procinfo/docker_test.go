package procinfo

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/guillaume86/autofwd/internal/procnet"
)

// dockerOutput fakes a lookup on a host where root runs dockerd: one
// docker-proxy per published address, as Docker starts them.
func dockerOutput(docker string) string {
	proxy := func(pid, hostIP, hostPort, contIP, contPort string) string {
		return "==> /proc/" + pid + "/cmdline <==\n" + strings.Join([]string{"/usr/bin/docker-proxy",
			"-proto", "tcp", "-host-ip", hostIP, "-host-port", hostPort,
			"-container-ip", contIP, "-container-port", contPort, "-use-listen-fd"}, "\x00") + "\x00\n"
	}
	return "@@autofwd id\n1000\n/home/dev\n50\n" +
		"@@autofwd stat\n1 (systemd) S 0\n900 (dockerd) S 1\n" +
		"901 (docker-proxy) S 900\n902 (docker-proxy) S 900\n903 (docker-proxy) S 900\n904 (docker-proxy) S 900\n" +
		"@@autofwd docker\n" + docker +
		"@@autofwd cmdline\n==> /dev/null <==\n\n==> /proc/1/cmdline <==\n/sbin/init\x00\n" +
		proxy("901", "0.0.0.0", "5432", "172.17.0.2", "5432") +
		proxy("902", "::", "5432", "fd00::2", "5432") +
		proxy("903", "127.0.0.1", "8080", "172.18.0.3", "80") +
		proxy("904", "192.168.1.5", "8080", "172.18.0.4", "80") +
		"@@autofwd end\n"
}

var dockerListeners = []procnet.Listener{
	listener("0.0.0.0:5432", 0, 1),
	listener("[::]:5432", 0, 2),
	listener("127.0.0.1:8080", 0, 3),
	listener("192.168.1.5:8080", 0, 4),
}

func TestParseDocker(t *testing.T) {
	ps := "shop-db-1 0.0.0.0:5432->5432/tcp, [::]:5432->5432/tcp\n" +
		"web 127.0.0.1:8080->80/tcp, 443/tcp\n" +
		"web-lan 192.168.1.5:8080->80/tcp\n" +
		"dns 0.0.0.0:53->53/udp\n"
	env, got := Parse([]byte(dockerOutput(ps)), dockerListeners)
	for ino, w := range map[uint64]struct {
		pid   int
		name  string
		addr  string
		label string
	}{
		1: {901, "shop-db-1", "172.17.0.2:5432", "docker-proxy  shop-db-1"},
		2: {902, "shop-db-1", "[fd00::2]:5432", "docker-proxy  shop-db-1"},
		3: {903, "web", "172.18.0.3:80", "docker-proxy  web"},         // the listener's address decides
		4: {904, "web-lan", "172.18.0.4:80", "docker-proxy  web-lan"}, // between containers on one port
	} {
		s := got[ino]
		if s.Proc == nil || s.Proc.PID != w.pid || !s.NamesPort {
			t.Errorf("inode %d: socket %+v proc %+v, want pid %d", ino, s, s.Proc, w.pid)
			continue
		}
		if s.Container.Name != w.name || s.Container.Addr.String() != w.addr {
			t.Errorf("inode %d: container %+v, want %s at %s", ino, s.Container, w.name, w.addr)
		}
		if l := s.Label(env.Home); l != w.label {
			t.Errorf("inode %d: label %q, want %q", ino, l, w.label)
		}
	}
}

func TestParseDockerWithoutCLI(t *testing.T) {
	// No docker access: the section is empty and the address stands in.
	env, got := Parse([]byte(dockerOutput("")), dockerListeners)
	for ino, label := range map[uint64]string{
		1: "docker-proxy  172.17.0.2:5432",
		2: "docker-proxy  [fd00::2]:5432",
		3: "docker-proxy  172.18.0.3:80",
	} {
		if s := got[ino]; s.Container.Name != "" || s.Label(env.Home) != label {
			t.Errorf("inode %d: container %+v label %q, want %q", ino, s.Container, s.Label(env.Home), label)
		}
	}
}

func TestDockerLabelAsRoot(t *testing.T) {
	// Logged in as root, docker-proxy's cwd is readable; the container is
	// the useful part.
	s := Socket{Proc: &Process{Name: "docker-proxy", Cwd: "/"}, Container: Container{Name: "db"}}
	if l := s.Label("/root"); l != "docker-proxy  db" {
		t.Errorf("label %q", l)
	}
}

func TestDockerContainerName(t *testing.T) {
	addr := netip.MustParseAddr("0.0.0.0")
	const cmd = "docker-proxy -host-ip 0.0.0.0 -host-port 8001 -container-ip 172.17.0.9 -container-port 9001"
	for _, tt := range []struct {
		desc, cmd, ps string
		port          uint16
		want          Container
	}{
		{"range", "docker-proxy --host-port=8000 --host-port-end=8002 --container-ip=172.17.0.9 --container-port=9000",
			"app 0.0.0.0:8000-8002->9000-9002/tcp\n", 8001,
			Container{Name: "app", Addr: netip.MustParseAddrPort("172.17.0.9:9001")}},
		{"other container port", cmd, "app 0.0.0.0:8001->80/tcp\n", 8001,
			Container{Addr: netip.MustParseAddrPort("172.17.0.9:9001")}},
		{"ambiguous", cmd, "a 10.0.0.1:8001->9001/tcp\nb 10.0.0.2:8001->9001/tcp\n", 8001,
			Container{Addr: netip.MustParseAddrPort("172.17.0.9:9001")}},
		{"old IPv6 format", cmd, "app :::8001->9001/tcp\n", 8001,
			Container{Name: "app", Addr: netip.MustParseAddrPort("172.17.0.9:9001")}},
		{"no container flags", "docker-proxy -host-port 8001", "app 0.0.0.0:8001->9001/tcp\n", 8001,
			Container{Name: "app"}},
		{"garbage", cmd, "junk\napp nonsense->x/tcp, 0.0.0.0:abc->1/tcp\n", 8001,
			Container{Addr: netip.MustParseAddrPort("172.17.0.9:9001")}},
	} {
		got := container(tt.cmd, addr, tt.port, parseDockerPS([]byte(tt.ps)))
		if got != tt.want {
			t.Errorf("%s: got %+v, want %+v", tt.desc, got, tt.want)
		}
	}
}
