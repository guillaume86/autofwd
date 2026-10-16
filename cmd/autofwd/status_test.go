package main

import (
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/guillaume86/autofwd/internal/forward"
	"github.com/guillaume86/autofwd/internal/supervisor"
)

func sampleStatus(now time.Time) supervisor.Status {
	return supervisor.Status{
		Dest:          "devbox",
		State:         supervisor.Connected,
		Since:         now.Add(-(2*time.Hour + 14*time.Minute)),
		LastKeepalive: now.Add(-12 * time.Second),
		Forwards: []forward.PortStatus{
			{Port: 3000, Target: netip.MustParseAddrPort("127.0.0.1:3000"), Since: now.Add(-90 * time.Minute), Conns: 3},
			{Port: 5173, Target: netip.MustParseAddrPort("[::1]:5173"), Since: now.Add(-40 * time.Second), Conns: 0},
		},
		Busy:    []forward.BusyStatus{{Port: 9229, Reason: "local port busy: another local process listens on it", RetryAt: now.Add(18 * time.Second)}},
		Skipped: []supervisor.Skipped{{Port: 22, Reason: "below --min-port 1024"}, {Port: 631, Reason: "below --min-port 1024"}, {Port: 5432, Reason: "in --ignore"}},
	}
}

func TestFormatStatusWide(t *testing.T) {
	now := time.Now()
	lines := formatStatus(sampleStatus(now), 100, now)
	out := strings.Join(lines, "\n")
	t.Log("\n" + out)
	for _, want := range []string{
		"devbox  ● connected 2h14m", "keepalive 12s ago", "[s]hide",
		"1  3000   http://localhost:3000    127.0.0.1        1h30m   3",
		"2  5173   http://localhost:5173    ::1              40s     0",
		"9229   — busy", "retry in 18s", "another local process",
		"skipped: 22 631 (below --min-port 1024)   5432 (in --ignore)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("wide output lacks %q", want)
		}
	}
	for i, l := range lines {
		if n := len([]rune(l)); n > 100 {
			t.Errorf("line %d is %d wide: %q", i, n, l)
		}
	}
}

func TestFormatStatusNarrow(t *testing.T) {
	now := time.Now()
	lines := formatStatus(sampleStatus(now), 60, now)
	out := strings.Join(lines, "\n")
	t.Log("\n" + out)
	for _, want := range []string{"[s] [v] [o] [r] [q]", "1 3000  http://localhost:3000  1h30m  3", "2 5173  http://localhost:5173 ::1  40s  0", "9229  busy, retry in 18s"} {
		if !strings.Contains(out, want) {
			t.Errorf("narrow output lacks %q", want)
		}
	}
	if strings.Contains(out, "LOCAL URL") {
		t.Error("narrow output has the header row")
	}
	for i, l := range lines {
		if n := len([]rune(l)); n > 60 {
			t.Errorf("line %d is %d wide: %q", i, n, l)
		}
	}
}

func TestFormatStatusStates(t *testing.T) {
	now := time.Now()
	st := supervisor.Status{Dest: "devbox", State: supervisor.Waiting, RetryAt: now.Add(8 * time.Second), LastError: "cannot resolve devbox: no such host"}
	out := strings.Join(formatStatus(st, 100, now), "\n")
	if !strings.Contains(out, "reconnecting in 8s") || !strings.Contains(out, "no such host") {
		t.Errorf("waiting state: %s", out)
	}
	st = supervisor.Status{Dest: "devbox", State: supervisor.Connected, Since: now}
	if out := strings.Join(formatStatus(st, 100, now), "\n"); !strings.Contains(out, "no ports forwarded yet") {
		t.Errorf("empty connected state: %s", out)
	}
	if got := statusPorts(sampleStatus(now)); len(got) != 2 || got[0] != 3000 || got[1] != 5173 {
		t.Errorf("statusPorts = %v", got)
	}
}

func TestFmtAge(t *testing.T) {
	for d, want := range map[time.Duration]string{
		0: "0s", 45 * time.Second: "45s", 3 * time.Minute: "3m", 2 * time.Hour: "2h",
		2*time.Hour + 14*time.Minute: "2h14m", 50 * time.Hour: "2d", -5 * time.Second: "0s",
	} {
		if got := fmtAge(d); got != want {
			t.Errorf("fmtAge(%v) = %q, want %q", d, got, want)
		}
	}
}
