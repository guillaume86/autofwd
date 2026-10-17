package procinfo

import (
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"

	"github.com/guillaume86/autofwd/internal/procnet"
)

// TestScriptOnThisHost runs the real script with the local sh against a
// socket this test opens, so the shell side is checked on every Linux CI run.
func TestScriptOnThisHost(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("needs Linux /proc")
	}
	if _, err := exec.LookPath("sh"); err != nil {
		t.Skip("no sh")
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)

	table, err := os.ReadFile("/proc/net/tcp")
	if err != nil {
		t.Fatal(err)
	}
	all, _ := procnet.Parse(table)
	var mine []procnet.Listener
	for _, l := range all {
		if l.Port == port {
			mine = append(mine, l)
		}
	}
	if len(mine) != 1 || !mine[0].HasOwner() {
		t.Fatalf("own listener not in /proc/net/tcp: %v", mine)
	}

	cmd := exec.Command("sh", "-s")
	cmd.Stdin = strings.NewReader(Script([]uint64{mine[0].Inode}))
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("script: %v\n%s", err, out)
	}
	env, got := Parse(out, mine)
	if env.UID != os.Getuid() {
		t.Errorf("uid %d, want %d", env.UID, os.Getuid())
	}
	s := got[mine[0].Inode]
	if s.Proc == nil || s.Proc.PID != os.Getpid() {
		t.Fatalf("socket = %+v, proc %+v; want pid %d\n%s", s, s.Proc, os.Getpid(), out)
	}
	wd, _ := os.Getwd()
	if s.Proc.Cwd != wd {
		t.Errorf("cwd %q, want %q", s.Proc.Cwd, wd)
	}
	if !strings.Contains(s.Proc.Cmdline, "procinfo.test") {
		t.Errorf("cmdline %q", s.Proc.Cmdline)
	}
	t.Logf("env: %s; label: %s", env.Describe(), s.Label(env.Home))
}
