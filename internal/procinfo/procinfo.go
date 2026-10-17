// Package procinfo finds which remote process owns each listening socket.
//
// Everything is read with stock tools from /proc, the way VS Code's port
// detection does it, so nothing is installed on the remote host:
//
//   - ls -l /proc/*/fd/ maps a socket inode to the processes holding it. It
//     only works for the SSH user's own processes.
//   - /proc/*/stat, /proc/*/cmdline and /proc/*/cwd describe a process.
//     Command lines are readable for every user unless /proc is mounted
//     with hidepid; cwd only for the user's own processes.
//   - ss -e, when iproute2 is installed and the kernel reports it, gives
//     the cgroup (systemd unit) of every socket, other users' included.
//     /proc/*/cgroup then says which processes are in that cgroup.
//
// The script prints each source in a marked section and all parsing happens
// here, so a missing tool or an unreadable file only empties its section.
package procinfo

import (
	"bytes"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"

	"github.com/guillaume86/autofwd/internal/procnet"
)

// Command runs the script, which is sent on stdin. Passing it as the command
// string would go through the user's login shell, which may not be POSIX
// (fish, for one).
const Command = "sh -s"

// marker starts each section of the script's output.
const marker = "@@autofwd "

// Script returns the shell script that collects everything needed to resolve
// the given socket inodes. It sticks to POSIX sh and to options that GNU
// coreutils and BusyBox share. /dev/null is listed first wherever a command
// takes many files so that ls and head always print per-file headers, even
// if only one /proc entry matches.
func Script(inodes []uint64) string {
	var fd strings.Builder
	for _, ino := range inodes {
		fmt.Fprintf(&fd, " -e 'socket:[%d]'", ino)
	}
	return `LC_ALL=C; export LC_ALL
echo '` + marker + `id'
id -u 2>/dev/null; echo "$HOME"; echo "$$"
echo '` + marker + `passwd'
cut -d: -f1,3 /etc/passwd 2>/dev/null
echo '` + marker + `fd'
ls -l /dev/null /proc/[0-9]*/fd/ 2>/dev/null | grep -F -e '/proc/'` + fd.String() + `
echo '` + marker + `cwd'
ls -l /dev/null /proc/[0-9]*/cwd 2>/dev/null | grep -F ' -> '
echo '` + marker + `stat'
cat /proc/[0-9]*/stat 2>/dev/null
echo '` + marker + `ss'
ss -tlne 2>/dev/null
echo '` + marker + `cgroup'
head -n 64 /dev/null /proc/[0-9]*/cgroup 2>/dev/null
echo '` + marker + `cmdline'
head -c 2048 /dev/null /proc/[0-9]*/cmdline 2>/dev/null
echo
echo '` + marker + `end'
`
}

// Env is what the remote host lets the SSH user see. It is reported by every
// lookup, so it stays current across reconnects.
type Env struct {
	UID   int // the SSH user's uid; -1 when unknown
	Home  string
	Users map[uint32]string // uid to user name, from /etc/passwd
	// OthersVisible is true when other users' command lines can be read,
	// which the Docker-proxy heuristic needs. hidepid turns it off.
	OthersVisible bool
	// Cgroups is true when ss reported socket cgroups.
	Cgroups bool
}

// UserName returns the name for uid, or "uid N" when it is not known.
func (e Env) UserName(uid uint32) string {
	if n, ok := e.Users[uid]; ok {
		return n
	}
	return "uid " + strconv.FormatUint(uint64(uid), 10)
}

// Describe summarizes the detected capabilities for a verbose log line.
func (e Env) Describe() string {
	var parts []string
	if e.UID >= 0 {
		parts = append(parts, fmt.Sprintf("uid %d", e.UID))
	} else {
		parts = append(parts, "uid unknown")
	}
	if e.OthersVisible {
		parts = append(parts, "other users' processes visible")
	} else {
		parts = append(parts, "other users' processes hidden")
	}
	if e.Cgroups {
		parts = append(parts, "socket cgroups from ss")
	}
	return strings.Join(parts, ", ")
}

// Process is one remote process.
type Process struct {
	PID, PPID int
	Name      string // the kernel's process name (comm), else argv[0]'s base name
	Cmdline   string // arguments joined with spaces; "" for kernel threads
	Cwd       string // "" when not readable (another user's process)
	Cgroup    string // cgroup v2 path, or the systemd hierarchy's on v1
}

// Socket is what is known about one listening socket.
type Socket struct {
	Proc *Process // nil when no process could be attributed
	Unit string   // systemd unit from the socket's cgroup, if ss reported one
	// NamesPort is true when the process's command line mentions the port,
	// the signature of a proxy such as Docker's that listens on behalf of
	// another user.
	NamesPort bool
}

// Known reports whether anything was found.
func (s Socket) Known() bool { return s.Proc != nil || s.Unit != "" }

// Label is the short description shown next to a forwarded port: the
// process name and its working directory, or the unit name.
func (s Socket) Label(home string) string {
	switch {
	case s.Proc != nil && s.Proc.Cwd != "":
		return s.Proc.Name + "  " + tilde(s.Proc.Cwd, home)
	case s.Proc != nil:
		return s.Proc.Name
	default:
		return s.Unit
	}
}

func tilde(dir, home string) string {
	if home == "" || home == "/" {
		return dir
	}
	if dir == home {
		return "~"
	}
	if rest, ok := strings.CutPrefix(dir, home+"/"); ok {
		return "~/" + rest
	}
	return dir
}

// Parse reads the script's output and resolves each listener's socket. The
// result is keyed by inode and has an entry for every listener asked about,
// with a zero Socket when nothing was found.
func Parse(out []byte, ls []procnet.Listener) (Env, map[uint64]Socket) {
	sec := sections(out)
	env := Env{UID: -1, Users: make(map[uint32]string)}

	self := -1 // the script's shell
	if lines := strings.Split(strings.TrimSpace(string(sec["id"])), "\n"); len(lines) >= 1 {
		if uid, err := strconv.Atoi(strings.TrimSpace(lines[0])); err == nil {
			env.UID = uid
		}
		if len(lines) >= 2 {
			env.Home = strings.TrimSpace(lines[1])
		}
		if len(lines) >= 3 {
			if pid, err := strconv.Atoi(strings.TrimSpace(lines[2])); err == nil {
				self = pid
			}
		}
	}
	for line := range strings.Lines(string(sec["passwd"])) {
		name, id, ok := strings.Cut(strings.TrimSpace(line), ":")
		if uid, err := strconv.ParseUint(id, 10, 32); ok && err == nil {
			env.Users[uint32(uid)] = name
		}
	}

	procs := parseStat(sec["stat"])
	for pid, c := range blocks(sec["cmdline"], "cmdline") {
		p := procs.get(pid)
		args := strings.Split(strings.TrimRight(c, "\x00"), "\x00")
		p.Cmdline = strings.TrimSpace(strings.Join(args, " "))
		if p.Name == "" && args[0] != "" {
			p.Name = path.Base(args[0])
		}
	}
	// pid 1 always belongs to someone else unless the SSH user is root or
	// the host is a container started as that user; either way, a readable
	// command line there means /proc is not hiding other users.
	if p := procs[1]; p != nil && p.Cmdline != "" {
		env.OthersVisible = true
	}
	for pid, c := range blocks(sec["cgroup"], "cgroup") {
		procs.get(pid).Cgroup = parseCgroup(c)
	}
	// The script's own commands are not candidates: grep's arguments carry
	// inode numbers that could pass for a port.
	for pid, p := range procs {
		if self > 0 && (pid == self || p.PPID == self) {
			delete(procs, pid)
		}
	}
	for line := range strings.Lines(string(sec["cwd"])) {
		if m := cwdLine.FindStringSubmatch(strings.TrimRight(line, "\r\n")); m != nil {
			pid, _ := strconv.Atoi(m[1])
			procs.get(pid).Cwd = m[2]
		}
	}
	holders := parseFD(sec["fd"])
	sockCgroups := parseSS(sec["ss"])
	env.Cgroups = len(sockCgroups) > 0

	res := make(map[uint64]Socket, len(ls))
	for _, l := range ls {
		if l.Inode == 0 {
			continue
		}
		if _, done := res[l.Inode]; done {
			continue
		}
		res[l.Inode] = resolve(l, procs, holders[l.Inode], sockCgroups[l.Inode], env)
	}
	return env, res
}

func resolve(l procnet.Listener, procs procTable, holders []int, cgroup string, env Env) Socket {
	var s Socket
	if cgroup != "" {
		s.Unit = unitName(cgroup)
	}
	// Exact: the user's own process holds the socket. A forked server's
	// children hold it too; the parent is the one to name.
	if len(holders) > 0 {
		p := topmost(procs, holders)
		return Socket{Proc: p, Unit: s.Unit, NamesPort: mentionsPort(p.Cmdline, l.Port)}
	}
	// The socket's cgroup narrows the candidates: a unit with a single
	// process is exact, otherwise fall through to the port heuristic within
	// the unit.
	candidates := procs.all()
	if cgroup != "" {
		var members []*Process
		for _, p := range candidates {
			if p.Cgroup == cgroup && p.Cmdline != "" {
				members = append(members, p)
			}
		}
		if len(members) == 1 {
			s.Proc = members[0]
			s.NamesPort = mentionsPort(members[0].Cmdline, l.Port)
			return s
		}
		if len(members) > 1 {
			candidates = members
		}
	}
	// Heuristic (VS Code's): a process whose command line names the port,
	// as Docker's proxy does with -host-port. Prefer the deepest descendant.
	var matches []*Process
	for _, p := range candidates {
		if mentionsPort(p.Cmdline, l.Port) {
			matches = append(matches, p)
		}
	}
	if len(matches) > 0 {
		s.Proc, s.NamesPort = deepest(matches), true
	}
	return s
}

// topmost picks the holder whose parent is not itself a holder, the lowest
// pid on ties.
func topmost(procs procTable, pids []int) *Process {
	slices.Sort(pids)
	for _, pid := range pids {
		if p := procs[pid]; p != nil && !slices.Contains(pids, p.PPID) {
			return p
		}
	}
	return procs.get(pids[0])
}

// deepest picks a match none of whose children also match, the lowest pid
// on ties.
func deepest(ms []*Process) *Process {
	slices.SortFunc(ms, func(a, b *Process) int { return a.PID - b.PID })
	for _, m := range ms {
		if !slices.ContainsFunc(ms, func(c *Process) bool { return c.PPID == m.PID }) {
			return m
		}
	}
	return ms[0]
}

// mentionsPort reports whether cmdline contains port as a whole number, so
// that 80 does not match 8080.
func mentionsPort(cmdline string, port uint16) bool {
	p := strconv.Itoa(int(port))
	for i := 0; ; {
		j := strings.Index(cmdline[i:], p)
		if j < 0 {
			return false
		}
		start, end := i+j, i+j+len(p)
		if (start == 0 || !isDigit(cmdline[start-1])) && (end == len(cmdline) || !isDigit(cmdline[end])) {
			return true
		}
		i = start + 1
	}
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }

// unitName turns a cgroup path into the systemd unit it belongs to, or ""
// for the root cgroup or one without a unit suffix.
func unitName(cgroup string) string {
	base := path.Base(cgroup)
	for _, suffix := range []string{".service", ".socket", ".scope"} {
		if strings.HasSuffix(base, suffix) {
			return base
		}
	}
	return ""
}

type procTable map[int]*Process

func (t procTable) get(pid int) *Process {
	p := t[pid]
	if p == nil {
		p = &Process{PID: pid}
		t[pid] = p
	}
	return p
}

func (t procTable) all() []*Process {
	out := make([]*Process, 0, len(t))
	for _, p := range t {
		out = append(out, p)
	}
	slices.SortFunc(out, func(a, b *Process) int { return a.PID - b.PID })
	return out
}

// sections splits the output on marker lines. Anything before the first
// marker (a chatty login shell) is ignored.
func sections(out []byte) map[string][]byte {
	sec := make(map[string][]byte)
	name := ""
	start := -1
	for i := 0; i <= len(out); {
		end := bytes.IndexByte(out[i:], '\n')
		if end < 0 {
			end = len(out)
		} else {
			end += i
		}
		line := out[i:end]
		if rest, ok := bytes.CutPrefix(line, []byte(marker)); ok {
			if start >= 0 {
				sec[name] = out[start:i]
			}
			name, start = string(bytes.TrimSpace(rest)), end+1
		}
		i = end + 1
	}
	if start >= 0 && start <= len(out) {
		sec[name] = out[start:]
	}
	return sec
}

var (
	blockHeader = regexp.MustCompile(`(?m)^==> /proc/(\d+)/(\w+) <==\n`)
	cwdLine     = regexp.MustCompile(`/proc/(\d+)/cwd -> (.*)$`)
	fdHeader    = regexp.MustCompile(`^/proc/(\d+)/fd/?:$`)
	fdSocket    = regexp.MustCompile(`-> socket:\[(\d+)\]$`)
)

// blocks splits head's multi-file output into each /proc/<pid>/<file>'s
// content. head separates files with a blank line, which is dropped.
func blocks(sec []byte, file string) map[int]string {
	out := make(map[int]string)
	locs := blockHeader.FindAllSubmatchIndex(sec, -1)
	for i, loc := range locs {
		end := len(sec)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		if string(sec[loc[4]:loc[5]]) != file {
			continue
		}
		pid, err := strconv.Atoi(string(sec[loc[2]:loc[3]]))
		if err != nil {
			continue
		}
		out[pid] = strings.TrimSuffix(string(sec[loc[1]:end]), "\n")
	}
	return out
}

// parseStat reads /proc/<pid>/stat lines: "pid (comm) state ppid ...". The
// name may itself contain spaces and parentheses, so it ends at the last ')'.
func parseStat(sec []byte) procTable {
	t := make(procTable)
	for line := range strings.Lines(string(sec)) {
		open := strings.IndexByte(line, '(')
		close := strings.LastIndexByte(line, ')')
		if open < 1 || close < open {
			continue
		}
		pid, err := strconv.Atoi(strings.TrimSpace(line[:open]))
		if err != nil {
			continue
		}
		rest := strings.Fields(line[close+1:])
		if len(rest) < 2 {
			continue
		}
		ppid, _ := strconv.Atoi(rest[1])
		p := t.get(pid)
		p.Name, p.PPID = line[open+1:close], ppid
	}
	return t
}

// parseCgroup picks the unified (v2) path, or systemd's on a v1 host.
func parseCgroup(content string) string {
	var v1 string
	for line := range strings.Lines(content) {
		line = strings.TrimSpace(line)
		if p, ok := strings.CutPrefix(line, "0::"); ok {
			return p
		}
		if _, p, ok := strings.Cut(line, ":name=systemd:"); ok {
			v1 = p
		}
	}
	return v1
}

// parseFD reads `ls -l /proc/*/fd/` output: a "/proc/<pid>/fd/:" header,
// then one "N -> socket:[inode]" line per descriptor.
func parseFD(sec []byte) map[uint64][]int {
	out := make(map[uint64][]int)
	pid := -1
	for line := range strings.Lines(string(sec)) {
		line = strings.TrimRight(line, "\r\n")
		if m := fdHeader.FindStringSubmatch(line); m != nil {
			pid, _ = strconv.Atoi(m[1])
			continue
		}
		if m := fdSocket.FindStringSubmatch(line); m != nil && pid > 0 {
			ino, _ := strconv.ParseUint(m[1], 10, 64)
			if !slices.Contains(out[ino], pid) {
				out[ino] = append(out[ino], pid)
			}
		}
	}
	return out
}

// parseSS reads `ss -tlne`: each socket row carries "ino:N" and, on
// kernels and iproute2 versions that report it, "cgroup:/path".
func parseSS(sec []byte) map[uint64]string {
	out := make(map[uint64]string)
	for line := range strings.Lines(string(sec)) {
		var ino uint64
		var cg string
		for _, f := range strings.Fields(line) {
			if v, ok := strings.CutPrefix(f, "ino:"); ok {
				ino, _ = strconv.ParseUint(v, 10, 64)
			} else if v, ok := strings.CutPrefix(f, "cgroup:"); ok {
				cg = v
			}
		}
		if ino != 0 && cg != "" && cg != "/" {
			out[ino] = cg
		}
	}
	return out
}
