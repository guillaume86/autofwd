package sshtest

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

// LogBuffer is a goroutine-safe io.Writer for capturing logs.
type LogBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *LogBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *LogBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// FreePort finds a port free on both 127.0.0.1 and ::1.
func FreePort(t testing.TB) uint16 {
	t.Helper()
	for range 50 {
		l, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		p := l.Addr().(*net.TCPAddr).Port
		l.Close()
		l6, err := net.Listen("tcp6", fmt.Sprintf("[::1]:%d", p))
		if err == nil {
			l6.Close()
			return uint16(p)
		}
		if !strings.Contains(err.Error(), "in use") && !strings.Contains(err.Error(), "normally permitted") {
			return uint16(p) // no IPv6 loopback on this machine
		}
	}
	t.Fatal("no free port found")
	return 0
}

// HasIPv6Loopback reports whether ::1 can be bound here.
func HasIPv6Loopback() bool {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		return false
	}
	l.Close()
	return true
}

// Eventually polls cond until it holds or the timeout expires.
func Eventually(t testing.TB, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Row is one socket for a fake /proc/net/tcp{,6} table.
type Row struct {
	Local  string // "0.0.0.0:3000", "[::1]:3000"
	Remote string // optional, defaults to the wildcard
	State  string // "0A" for LISTEN, "01" ESTABLISHED, ...
}

// ProcTables renders rows as `cat /proc/net/tcp /proc/net/tcp6` would.
func ProcTables(rows ...Row) string {
	var v4, v6 strings.Builder
	v4.WriteString("  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	v6.WriteString("  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n")
	n4, n6 := 0, 0
	for _, r := range rows {
		local := netip.MustParseAddrPort(r.Local)
		remote := netip.AddrPortFrom(netip.IPv4Unspecified(), 0)
		if local.Addr().Is6() {
			remote = netip.AddrPortFrom(netip.IPv6Unspecified(), 0)
		}
		if r.Remote != "" {
			remote = netip.MustParseAddrPort(r.Remote)
		}
		line := fmt.Sprintf("%s %s %s 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0000000000000000 100 0 0 10 0\n",
			encode(local), encode(remote), r.State)
		if local.Addr().Is4() {
			fmt.Fprintf(&v4, "%4d: %s", n4, line)
			n4++
		} else {
			fmt.Fprintf(&v6, "%4d: %s", n6, line)
			n6++
		}
	}
	return v4.String() + v6.String()
}

// encode is the inverse of the kernel's per-32-bit-word little-endian dump.
func encode(ap netip.AddrPort) string {
	b := ap.Addr().AsSlice()
	for w := 0; w < len(b); w += 4 {
		b[w], b[w+1], b[w+2], b[w+3] = b[w+3], b[w+2], b[w+1], b[w]
	}
	return fmt.Sprintf("%s:%04X", strings.ToUpper(hex.EncodeToString(b)), ap.Port())
}
