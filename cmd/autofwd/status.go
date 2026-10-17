package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/guillaume86/autofwd/internal/forward"
	"github.com/guillaume86/autofwd/internal/supervisor"
)

// maxStatusRows caps the forwarded-port rows so the footer never swallows
// the screen; the digit shortcuts only reach the first nine anyway.
const maxStatusRows = 9

// formatStatus renders the status footer for the given terminal width.
func formatStatus(st supervisor.Status, width int, now time.Time) []string {
	narrow := width < 80
	rule := strings.Repeat("─", max(min(width, 120), 20))
	lines := []string{rule}

	// Header: connection state, then key hints right-aligned when they fit.
	var state string
	switch st.State {
	case supervisor.Connected:
		state = "● connected " + fmtAge(now.Sub(st.Since))
	case supervisor.Waiting:
		state = fmt.Sprintf("○ reconnecting in %s", fmtAge(st.RetryAt.Sub(now)))
	default:
		state = "○ connecting"
	}
	head := " " + st.Dest + "  " + state
	if !narrow && st.State == supervisor.Connected && !st.LastKeepalive.IsZero() {
		head += fmt.Sprintf("   keepalive %s ago", fmtAge(now.Sub(st.LastKeepalive)))
	}
	hints := "[o]pen [1-9] [r]efresh [v]erbose [q]uit"
	if narrow {
		hints = "[o] [1-9] [r] [v] [q]"
	}
	lines = append(lines, padBetween(head, hints, width))
	if st.State != supervisor.Connected && st.LastError != "" {
		lines = append(lines, "   "+truncate(st.LastError, width-3))
	}

	// Forwarded ports.
	if len(st.Forwards) == 0 && st.State == supervisor.Connected {
		lines = append(lines, "   no ports forwarded yet")
	}
	if len(st.Forwards) > 0 && !narrow {
		lines = append(lines, fmt.Sprintf("  %-2s %-6s %-24s %-16s %-7s %-5s %s", "#", "PORT", "LOCAL URL", "REMOTE", "AGE", "CONNS", "PROCESS"))
	}
	for i, f := range st.Forwards {
		if i == maxStatusRows {
			lines = append(lines, fmt.Sprintf("     … and %d more", len(st.Forwards)-maxStatusRows))
			break
		}
		url := forward.LocalURL(f.Port)
		age := fmtAge(now.Sub(f.Since))
		if narrow {
			remote := ""
			if f.Target.Addr().String() != "127.0.0.1" {
				remote = " " + f.Target.Addr().String()
			}
			row := fmt.Sprintf("  %d %-5d %s%s  %s  %d", i+1, f.Port, url, remote, age, f.Conns)
			if f.Label != "" {
				row += "  " + f.Label
			}
			lines = append(lines, truncate(row, width))
			continue
		}
		row := fmt.Sprintf("  %-2d %-6d %-24s %-16s %-7s %-5d %s", i+1, f.Port, url, f.Target.Addr(), age, f.Conns, f.Label)
		lines = append(lines, truncate(strings.TrimRight(row, " "), width))
	}

	// Busy ports.
	for _, b := range st.Busy {
		retry := "retry in " + fmtAge(b.RetryAt.Sub(now))
		if b.RetryAt.Before(now) {
			retry = "retrying"
		}
		if narrow {
			lines = append(lines, fmt.Sprintf("    %-5d busy, %s", b.Port, retry))
		} else {
			lines = append(lines, truncate(fmt.Sprintf("  %-2s %-6d %-24s %s  (%s)", "", b.Port, "— busy", retry, b.Reason), width))
		}
	}

	// Skipped ports, grouped by reason on one line. Ports skipped for their
	// process carry its name: "45747 containerd, 59041 tailscaled".
	if len(st.Skipped) > 0 {
		groups := make(map[string][]string)
		named := make(map[string]bool)
		var order []string
		for _, s := range st.Skipped {
			if _, ok := groups[s.Reason]; !ok {
				order = append(order, s.Reason)
			}
			item := fmt.Sprint(s.Port)
			if s.Process != "" {
				item += " " + s.Process
				named[s.Reason] = true
			}
			groups[s.Reason] = append(groups[s.Reason], item)
		}
		var parts []string
		for _, r := range order {
			sep := " "
			if named[r] {
				sep = ", "
			}
			parts = append(parts, strings.Join(groups[r], sep)+" ("+r+")")
		}
		lines = append(lines, truncate("     skipped: "+strings.Join(parts, "   "), width))
	}
	return lines
}

// statusPorts returns the ports in the order the status rows show them, so
// the digit keys can map to them.
func statusPorts(st supervisor.Status) []uint16 {
	out := make([]uint16, 0, len(st.Forwards))
	for i, f := range st.Forwards {
		if i == maxStatusRows {
			break
		}
		out = append(out, f.Port)
	}
	return out
}

// fmtAge prints a duration the way a human reads it: 45s, 3m, 2h14m, 3d.
func fmtAge(d time.Duration) string {
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 24*time.Hour:
		h := int(d.Hours())
		m := int(d.Minutes()) - 60*h
		if m == 0 {
			return fmt.Sprintf("%dh", h)
		}
		return fmt.Sprintf("%dh%02dm", h, m)
	default:
		return fmt.Sprintf("%dd", int(d.Hours()/24))
	}
}

// padBetween puts right at the right edge of a width-wide line if it fits,
// otherwise on its own after left.
func padBetween(left, right string, width int) string {
	gap := width - len([]rune(left)) - len([]rune(right))
	if gap < 2 {
		return left + "  " + right
	}
	return left + strings.Repeat(" ", gap) + right
}

func truncate(s string, width int) string {
	r := []rune(s)
	if width <= 1 || len(r) <= width {
		return s
	}
	return string(r[:width-1]) + "…"
}
