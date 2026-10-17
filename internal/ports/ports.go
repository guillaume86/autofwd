// Package ports decides which remote listeners become local forwards and
// which remote address each forward dials.
package ports

import (
	"cmp"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/guillaume86/autofwd/internal/procinfo"
	"github.com/guillaume86/autofwd/internal/procnet"
)

// Range is an inclusive port range.
type Range struct{ Lo, Hi uint16 }

// Set is a union of port ranges, such as "5432,6379,40000-50000".
type Set []Range

// ParseSet parses a comma-separated list of ports and inclusive ranges.
// Whitespace and empty items are ignored, so "" yields an empty set.
func ParseSet(s string) (Set, error) {
	var out Set
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(item, "-")
		l, err := parsePort(lo)
		if err != nil {
			return nil, fmt.Errorf("port list item %q: %w", item, err)
		}
		h := l
		if isRange {
			if h, err = parsePort(hi); err != nil {
				return nil, fmt.Errorf("port list item %q: %w", item, err)
			}
			if h < l {
				return nil, fmt.Errorf("port list item %q: range is reversed", item)
			}
		}
		out = append(out, Range{l, h})
	}
	return out, nil
}

func parsePort(s string) (uint16, error) {
	n, err := strconv.ParseUint(strings.TrimSpace(s), 10, 16)
	if err != nil || n == 0 {
		return 0, fmt.Errorf("%q is not a port number (1-65535)", s)
	}
	return uint16(n), nil
}

// Contains reports whether p is in any range of the set.
func (s Set) Contains(p uint16) bool {
	for _, r := range s {
		if p >= r.Lo && p <= r.Hi {
			return true
		}
	}
	return false
}

func (s Set) String() string {
	parts := make([]string, len(s))
	for i, r := range s {
		if r.Lo == r.Hi {
			parts[i] = strconv.Itoa(int(r.Lo))
		} else {
			parts[i] = fmt.Sprintf("%d-%d", r.Lo, r.Hi)
		}
	}
	return strings.Join(parts, ",")
}

// Filter selects the ports worth forwarding.
type Filter struct {
	MinPort uint16
	Ignore  Set
	// Only, when non-empty, is an allowlist that replaces every other rule.
	Only Set
	// AllUsers forwards other users' sockets too. Without it, a socket owned
	// by someone else is forwarded only when a process's command line names
	// its port, as Docker's proxy does.
	AllUsers bool
	// IgnoreProcess skips sockets whose process name, command line or
	// systemd unit matches one of these.
	IgnoreProcess []*regexp.Regexp
}

// DefaultIgnoreProcess lists the processes skipped unless the user sets
// their own list: daemons that listen on random high ports for their own
// use, and editor servers that do their own forwarding.
var DefaultIgnoreProcess = []string{
	`^tailscaled$`,
	`^containerd$`,
	`^dockerd$`,
	`^sshd$`,
	`/\.(vscode|cursor|windsurf)-server`,
}

// ProcessReason explains why listener l, whose socket was resolved to s, is
// not forwarded, or returns "" when it is. It complements Reason, which
// looks at the port number alone. Whatever env could not determine never
// excludes anything, so a host that hides process details behaves as if
// these rules did not exist.
func (f Filter) ProcessReason(l procnet.Listener, s procinfo.Socket, env procinfo.Env) string {
	if len(f.Only) > 0 {
		return ""
	}
	// The owner rule needs the user's uid, the socket's owner and the
	// ability to see other users' command lines; without the last one a
	// Docker-published port could not be told apart.
	if !f.AllUsers && env.UID >= 0 && env.OthersVisible && l.HasOwner() &&
		int64(l.UID) != int64(env.UID) && !s.NamesPort {
		return "owned by " + env.UserName(l.UID)
	}
	for _, re := range f.IgnoreProcess {
		if p := s.Proc; p != nil && (re.MatchString(p.Name) || (p.Cmdline != "" && re.MatchString(p.Cmdline))) {
			return "in --ignore-process"
		}
		if s.Unit != "" && re.MatchString(s.Unit) {
			return "in --ignore-process"
		}
	}
	return ""
}

// Allow reports whether port p should be forwarded.
func (f Filter) Allow(p uint16) bool { return f.Reason(p) == "" }

// Reason explains why port p is not forwarded, or returns "" when it is.
func (f Filter) Reason(p uint16) string {
	switch {
	case len(f.Only) > 0:
		if f.Only.Contains(p) {
			return ""
		}
		return "not in --only"
	case p < f.MinPort:
		return fmt.Sprintf("below --min-port %d", f.MinPort)
	case f.Ignore.Contains(p):
		return "in --ignore"
	}
	return ""
}

var (
	loopback4 = netip.MustParseAddr("127.0.0.1")
	loopback6 = netip.IPv6Loopback()
)

// rank orders the candidate dial addresses for one port; lower wins.
const (
	rankLoopback4 = iota // 0.0.0.0, ::, 127.0.0.0/8: dial 127.0.0.1
	rankSpecific4        // another IPv4 address the socket is bound to
	rankLoopback6        // ::1, only reached when nothing IPv4 listens
	rankSpecific6        // another IPv6 address
	rankUnusable
)

// dialAddr maps one listening address to the address autofwd should dial on
// the remote side, plus its rank among the listeners of the same port.
func dialAddr(a netip.Addr) (netip.Addr, int) {
	a = a.Unmap()
	switch {
	case a.IsUnspecified() || (a.Is4() && a.IsLoopback()):
		return loopback4, rankLoopback4
	case a.Is4():
		return a, rankSpecific4
	case a == loopback6:
		return loopback6, rankLoopback6
	case a.IsLinkLocalUnicast() && a.Zone() == "":
		// /proc/net/tcp6 does not record the interface, so a link-local
		// address cannot be dialed.
		return netip.Addr{}, rankUnusable
	default:
		return a, rankSpecific6
	}
}

// Select picks one remote dial target per port from the listening sockets,
// applying the filter. Listeners that cannot be dialed at all (link-local
// IPv6 without a known scope) are returned separately so they can be logged.
func Select(ls []procnet.Listener, f Filter) (targets map[uint16]netip.AddrPort, unusable []procnet.Listener) {
	type best struct {
		addr netip.Addr
		rank int
	}
	chosen := make(map[uint16]best)
	for _, l := range ls {
		if !f.Allow(l.Port) {
			continue
		}
		addr, rank := dialAddr(l.Addr)
		if rank == rankUnusable {
			unusable = append(unusable, l)
			continue
		}
		cur, ok := chosen[l.Port]
		// Ties between specific addresses go to the smallest, so the choice
		// does not flap with the kernel's row order.
		if !ok || rank < cur.rank || (rank == cur.rank && addr.Less(cur.addr)) {
			chosen[l.Port] = best{addr, rank}
		}
	}
	targets = make(map[uint16]netip.AddrPort, len(chosen))
	for port, b := range chosen {
		targets[port] = netip.AddrPortFrom(b.addr, port)
	}
	// A port with a usable listener is not "unusable", whatever its other rows say.
	unusable = slices.DeleteFunc(unusable, func(l procnet.Listener) bool {
		_, ok := targets[l.Port]
		return ok
	})
	slices.SortFunc(unusable, func(a, b procnet.Listener) int { return cmp.Compare(a.Port, b.Port) })
	return targets, unusable
}
