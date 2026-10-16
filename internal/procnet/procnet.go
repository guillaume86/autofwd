// Package procnet parses the Linux /proc/net/tcp and /proc/net/tcp6 tables.
//
// Addresses in those files are hex dumps of the in-kernel representation:
// each 32-bit word is printed with %08X in host byte order, so on the
// little-endian machines this tool targets (x86-64, arm64) the bytes of every
// word appear reversed. Ports are printed in host order already and need no
// swapping.
package procnet

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// StateListen is the kernel's TCP_LISTEN state as printed in the "st" column.
const StateListen = "0A"

// Listener is one listening socket.
type Listener struct {
	Addr netip.Addr // IPv4-mapped IPv6 addresses are unmapped to plain IPv4
	Port uint16
}

func (l Listener) String() string {
	return netip.AddrPortFrom(l.Addr, l.Port).String()
}

// Parse extracts every LISTEN socket from the concatenated contents of
// /proc/net/tcp and/or /proc/net/tcp6. Header lines are skipped wherever they
// appear. Malformed rows are skipped too; they are reported in the returned
// error, which is non-nil only alongside a still-usable result.
func Parse(data []byte) ([]Listener, error) {
	var (
		out  []Listener
		errs []error
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lineNo := 0
	for sc.Scan() {
		lineNo++
		fields := strings.Fields(sc.Text())
		if len(fields) == 0 || fields[0] == "sl" {
			continue
		}
		if len(fields) < 4 {
			errs = append(errs, fmt.Errorf("line %d: too few fields", lineNo))
			continue
		}
		if !strings.EqualFold(fields[3], StateListen) {
			continue
		}
		addr, port, err := parseHostPort(fields[1])
		if err != nil {
			errs = append(errs, fmt.Errorf("line %d: %w", lineNo, err))
			continue
		}
		out = append(out, Listener{Addr: addr, Port: port})
	}
	if err := sc.Err(); err != nil {
		errs = append(errs, err)
	}
	return out, errors.Join(errs...)
}

// parseHostPort decodes "0100007F:0BB8" or a 32-digit IPv6 form. An optional
// "%zone" between address and port is accepted: the kernel never prints one,
// but it lets fixtures and alternative sources carry link-local scopes.
func parseHostPort(s string) (netip.Addr, uint16, error) {
	i := strings.LastIndexByte(s, ':')
	if i < 0 {
		return netip.Addr{}, 0, fmt.Errorf("address %q: missing port", s)
	}
	hexAddr, hexPort := s[:i], s[i+1:]
	var zone string
	if j := strings.IndexByte(hexAddr, '%'); j >= 0 {
		hexAddr, zone = hexAddr[:j], hexAddr[j+1:]
	}

	port, err := strconv.ParseUint(hexPort, 16, 16)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("address %q: bad port: %w", s, err)
	}

	raw, err := hex.DecodeString(hexAddr)
	if err != nil {
		return netip.Addr{}, 0, fmt.Errorf("address %q: %w", s, err)
	}
	if len(raw) != 4 && len(raw) != 16 {
		return netip.Addr{}, 0, fmt.Errorf("address %q: unexpected length %d", s, len(raw))
	}
	// Undo the per-word byte swap.
	for w := 0; w < len(raw); w += 4 {
		raw[w], raw[w+1], raw[w+2], raw[w+3] = raw[w+3], raw[w+2], raw[w+1], raw[w]
	}

	var addr netip.Addr
	if len(raw) == 4 {
		addr = netip.AddrFrom4([4]byte(raw))
	} else {
		addr = netip.AddrFrom16([16]byte(raw))
		if addr.Is4In6() {
			addr = addr.Unmap() // a scope on a mapped address is meaningless
		} else if zone != "" {
			addr = addr.WithZone(zone)
		}
	}
	return addr, uint16(port), nil
}
