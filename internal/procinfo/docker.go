package procinfo

import (
	"net/netip"
	"strconv"
	"strings"
)

// dockerSection lists the running containers' names and published ports,
// as `name 0.0.0.0:8080->80/tcp, [::]:8080->80/tcp`. It only asks Docker
// when a docker-proxy runs, since there is nothing to name otherwise, and
// gives up after a few seconds should the daemon hang. Without access to the
// Docker socket the section stays empty. stdin is /dev/null so that nothing
// docker starts (an ssh:// context) can eat the rest of the script.
const dockerSection = `if grep -qsx docker-proxy /proc/[0-9]*/comm && command -v docker >/dev/null 2>&1; then
	t=; command -v timeout >/dev/null 2>&1 && t='timeout 5'
	$t docker ps --format '{{.Names}} {{.Ports}}' </dev/null 2>/dev/null
fi
`

// Container is the Docker container a docker-proxy forwards a port to.
type Container struct {
	Name string         // from docker ps; "" when the docker CLI could not be used
	Addr netip.AddrPort // the container's address, from docker-proxy's command line
}

// String is the container's name, else its address, else "".
func (c Container) String() string {
	if c.Name != "" {
		return c.Name
	}
	if c.Addr.IsValid() {
		return c.Addr.String()
	}
	return ""
}

// proxyArgs is what docker-proxy's command line says about one mapping:
// -host-ip 0.0.0.0 -host-port 8080 -container-ip 172.17.0.2 -container-port 80,
// with -host-port-end and -container-port-end for a range.
type proxyArgs struct {
	hostIP, container netip.Addr
	hostPort, hostEnd uint16
	contPort          uint16
}

func parseProxyArgs(cmdline string) proxyArgs {
	var a proxyArgs
	f := strings.Fields(cmdline)
	for i := 0; i < len(f); i++ {
		name, val, hasVal := strings.Cut(strings.TrimLeft(f[i], "-"), "=")
		if !hasVal {
			if i+1 >= len(f) {
				break
			}
			val = f[i+1]
		}
		used := true
		switch name {
		case "host-ip":
			a.hostIP, _ = netip.ParseAddr(val)
		case "container-ip":
			a.container, _ = netip.ParseAddr(val)
		case "host-port":
			a.hostPort = parsePort(val)
		case "host-port-end":
			a.hostEnd = parsePort(val)
		case "container-port":
			a.contPort = parsePort(val)
		default:
			used = false
		}
		if used && !hasVal {
			i++
		}
	}
	return a
}

// sameHostIP keeps the processes whose command line binds -host-ip addr:
// Docker starts one docker-proxy per published address, 0.0.0.0 and ::
// among them, and all of them name the same port. It returns ps unchanged
// when none does.
func sameHostIP(ps []*Process, addr netip.Addr) []*Process {
	var out []*Process
	for _, p := range ps {
		if ip := parseProxyArgs(p.Cmdline).hostIP; ip.IsValid() && ip.Unmap() == addr.Unmap() {
			out = append(out, p)
		}
	}
	if len(out) == 0 {
		return ps
	}
	return out
}

// containerPort is the container port that host port p maps to, or 0.
func (a proxyArgs) containerPort(p uint16) uint16 {
	if a.contPort == 0 {
		return 0
	}
	if a.hostPort != 0 && p > a.hostPort && p <= a.hostEnd {
		return a.contPort + (p - a.hostPort)
	}
	return a.contPort
}

func parsePort(s string) uint16 {
	n, err := strconv.ParseUint(s, 10, 16)
	if err != nil {
		return 0
	}
	return uint16(n)
}

// publishedPort is one TCP mapping from docker ps's Ports column.
type publishedPort struct {
	name           string
	hostIP         netip.Addr // invalid when unparsable
	hostLo, hostHi uint16
	contLo         uint16
}

// parseDockerPS reads `name ports` lines. A Ports entry looks like
// 0.0.0.0:8080->80/tcp, :::8080->80/tcp, [::]:8000-8001->8000-8001/tcp, or
// 80/tcp for a port that is exposed but not published.
func parseDockerPS(sec []byte) []publishedPort {
	var out []publishedPort
	for line := range strings.Lines(string(sec)) {
		name, ports, ok := strings.Cut(strings.TrimSpace(line), " ")
		if !ok || name == "" {
			continue
		}
		for e := range strings.SplitSeq(ports, ",") {
			host, cont, ok := strings.Cut(strings.TrimSpace(e), "->")
			if !ok {
				continue
			}
			contPorts, proto, _ := strings.Cut(cont, "/")
			colon := strings.LastIndexByte(host, ':')
			if proto != "tcp" || colon < 0 {
				continue
			}
			hostIP, _ := netip.ParseAddr(strings.Trim(host[:colon], "[]"))
			hLo, hHi := parseRange(host[colon+1:])
			cLo, _ := parseRange(contPorts)
			if hLo == 0 || cLo == 0 {
				continue
			}
			out = append(out, publishedPort{name: name, hostIP: hostIP, hostLo: hLo, hostHi: hHi, contLo: cLo})
		}
	}
	return out
}

// parseRange reads "8000" or "8000-8001"; zeros mean unparsable.
func parseRange(s string) (lo, hi uint16) {
	a, b, isRange := strings.Cut(s, "-")
	lo = parsePort(a)
	if !isRange {
		return lo, lo
	}
	hi = parsePort(b)
	if hi < lo {
		return 0, 0
	}
	return lo, hi
}

// container describes the container behind listener addr:port, held by a
// docker-proxy with command line cmdline. The name comes from the published
// ports with that host port and container port; where several containers
// publish the same port on different addresses, the listener's address
// decides. A name is only given when it is unambiguous.
func container(cmdline string, addr netip.Addr, port uint16, published []publishedPort) Container {
	a := parseProxyArgs(cmdline)
	cport := a.containerPort(port)
	var c Container
	if a.container.IsValid() && cport != 0 {
		c.Addr = netip.AddrPortFrom(a.container, cport)
	}
	var matches []publishedPort
	for _, p := range published {
		if port >= p.hostLo && port <= p.hostHi && (cport == 0 || p.contLo+(port-p.hostLo) == cport) {
			matches = append(matches, p)
		}
	}
	var exact []publishedPort
	for _, p := range matches {
		if p.hostIP.IsValid() && p.hostIP.Unmap() == addr.Unmap() {
			exact = append(exact, p)
		}
	}
	if len(exact) > 0 {
		matches = exact
	}
	for _, p := range matches {
		if c.Name != "" && c.Name != p.name {
			c.Name = ""
			break
		}
		c.Name = p.name
	}
	return c
}
