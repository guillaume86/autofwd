// Package sshconn turns a host alias into an authenticated SSH connection,
// following ~/.ssh/config, ssh-agent, key files, known_hosts and ProxyJump.
package sshconn

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/kevinburke/ssh_config"
)

// Host is the resolved connection settings for one destination.
type Host struct {
	Alias           string // what the user typed, minus any user@
	HostName        string
	Port            string
	User            string
	IdentityFiles   []string
	IdentitiesOnly  bool
	IdentityAgent   string // "" means the platform default; "none" disables the agent
	KnownHostsFiles []string
	HostKeyAlias    string
	ProxyJump       string
	ConnectTimeout  time.Duration
}

// knownHostsAddr is the host:port looked up in known_hosts, as ssh would
// write it: "[host]:port" for a non-standard port, but a bare HostKeyAlias
// whatever the port.
func (h Host) knownHostsAddr() string {
	if h.HostKeyAlias != "" {
		return net.JoinHostPort(h.HostKeyAlias, "22")
	}
	return net.JoinHostPort(h.HostName, h.Port)
}

// Resolver looks hosts up in the user's and the system's ssh_config.
type Resolver struct {
	configs   []*ssh_config.Config // user first: the first value found wins
	home      string
	localUser string
}

// ConfigError is a problem in ssh_config or the destination; retrying will
// not fix it.
type ConfigError struct{ Err error }

func (e *ConfigError) Error() string { return e.Err.Error() }
func (e *ConfigError) Unwrap() error { return e.Err }

// NewResolver loads the given ssh_config files, earlier ones taking
// precedence. With none, it loads ~/.ssh/config and the system-wide file.
// Missing files are fine; unparsable ones are not, because silently ignoring
// them could connect to the wrong machine.
func NewResolver(files ...string) (*Resolver, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, &ConfigError{fmt.Errorf("finding home directory: %w", err)}
	}
	r := &Resolver{home: home, localUser: localUsername()}
	if len(files) == 0 {
		files = []string{filepath.Join(home, ".ssh", "config"), systemConfigPath()}
	}
	for _, path := range files {
		cfg, err := loadConfig(path)
		if err != nil {
			return nil, &ConfigError{err}
		}
		if cfg != nil {
			r.configs = append(r.configs, cfg)
		}
	}
	return r, nil
}

func loadConfig(path string) (*ssh_config.Config, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()
	cfg, err := ssh_config.Decode(f)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return cfg, nil
}

func systemConfigPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "ssh", "ssh_config")
	}
	return "/etc/ssh/ssh_config"
}

func systemKnownHostsPath() string {
	if runtime.GOOS == "windows" {
		return filepath.Join(os.Getenv("ProgramData"), "ssh", "ssh_known_hosts")
	}
	return "/etc/ssh/ssh_known_hosts"
}

func localUsername() string {
	if u, err := user.Current(); err == nil && u.Username != "" {
		// Windows reports DOMAIN\user; ssh uses the bare name.
		if i := strings.LastIndexByte(u.Username, '\\'); i >= 0 {
			return u.Username[i+1:]
		}
		return u.Username
	}
	for _, env := range []string{"USER", "USERNAME"} {
		if v := os.Getenv(env); v != "" {
			return v
		}
	}
	return ""
}

func (r *Resolver) get(alias, key string) string {
	for _, c := range r.configs {
		if v, err := c.Get(alias, key); err == nil && v != "" {
			return v
		}
	}
	return ""
}

func (r *Resolver) getAll(alias, key string) []string {
	var out []string
	for _, c := range r.configs {
		if vs, err := c.GetAll(alias, key); err == nil {
			out = append(out, vs...)
		}
	}
	return out
}

// Resolve computes the settings for dest, which is "alias" or "user@alias".
func (r *Resolver) Resolve(dest string) (Host, error) {
	var h Host
	var userOverride, alias string
	if i := strings.LastIndexByte(dest, '@'); i >= 0 {
		userOverride, alias = dest[:i], dest[i+1:] // ssh splits at the last @
	} else {
		alias = dest
	}
	if alias == "" || strings.ContainsAny(alias, " \t") {
		return h, &ConfigError{fmt.Errorf("invalid destination %q", dest)}
	}
	h.Alias = alias

	if pc := r.get(alias, "ProxyCommand"); pc != "" && !strings.EqualFold(pc, "none") {
		return h, &ConfigError{fmt.Errorf("host %s uses ProxyCommand, which autofwd does not support (ProxyJump is supported)", alias)}
	}

	h.Port = r.get(alias, "Port")
	if h.Port == "" {
		h.Port = "22"
	}
	if n, err := strconv.ParseUint(h.Port, 10, 16); err != nil || n == 0 {
		return h, &ConfigError{fmt.Errorf("host %s: invalid Port %q", alias, h.Port)}
	}

	h.User = userOverride
	if h.User == "" {
		h.User = r.get(alias, "User")
	}
	if h.User == "" {
		h.User = r.localUser
	}

	// HostName may reference the alias as %h; expand with what we know so far.
	h.HostName = alias
	if hn := r.get(alias, "HostName"); hn != "" {
		h.HostName = r.expand(hn, h)
	}

	for _, f := range r.getAll(alias, "IdentityFile") {
		h.IdentityFiles = append(h.IdentityFiles, r.expand(f, h))
	}
	if len(h.IdentityFiles) == 0 {
		for _, name := range []string{"id_ed25519", "id_ecdsa", "id_rsa"} {
			h.IdentityFiles = append(h.IdentityFiles, filepath.Join(r.home, ".ssh", name))
		}
	}
	h.IdentitiesOnly = strings.EqualFold(r.get(alias, "IdentitiesOnly"), "yes")

	switch ia := r.get(alias, "IdentityAgent"); {
	case ia == "" || ia == "SSH_AUTH_SOCK":
	case strings.EqualFold(ia, "none"):
		h.IdentityAgent = "none"
	case strings.HasPrefix(ia, "$"):
		h.IdentityAgent = os.Getenv(strings.Trim(ia[1:], "{}"))
	default:
		h.IdentityAgent = r.expand(ia, h)
	}

	if ukh := r.get(alias, "UserKnownHostsFile"); ukh != "" {
		for f := range strings.FieldsSeq(ukh) {
			h.KnownHostsFiles = append(h.KnownHostsFiles, r.expand(f, h))
		}
	} else {
		h.KnownHostsFiles = []string{
			filepath.Join(r.home, ".ssh", "known_hosts"),
			filepath.Join(r.home, ".ssh", "known_hosts2"),
		}
	}
	if gkh := r.get(alias, "GlobalKnownHostsFile"); gkh != "" {
		for f := range strings.FieldsSeq(gkh) {
			h.KnownHostsFiles = append(h.KnownHostsFiles, r.expand(f, h))
		}
	} else {
		h.KnownHostsFiles = append(h.KnownHostsFiles, systemKnownHostsPath())
	}
	h.HostKeyAlias = r.get(alias, "HostKeyAlias")

	if pj := r.get(alias, "ProxyJump"); !strings.EqualFold(pj, "none") {
		h.ProxyJump = pj
	}

	if ct := r.get(alias, "ConnectTimeout"); ct != "" {
		if n, err := strconv.Atoi(ct); err == nil && n > 0 {
			h.ConnectTimeout = time.Duration(n) * time.Second
		}
	}
	return h, nil
}

// expand handles a leading ~ and the common ssh_config % tokens.
func (r *Resolver) expand(s string, h Host) string {
	s = strings.Trim(s, `"`)
	if s == "~" || strings.HasPrefix(s, "~/") || strings.HasPrefix(s, `~\`) {
		s = r.home + s[1:]
	}
	if !strings.Contains(s, "%") {
		return filepath.FromSlash(s)
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '%' || i+1 == len(s) {
			b.WriteByte(s[i])
			continue
		}
		i++
		switch s[i] {
		case '%':
			b.WriteByte('%')
		case 'd':
			b.WriteString(r.home)
		case 'u':
			b.WriteString(r.localUser)
		case 'h':
			b.WriteString(h.HostName)
		case 'n':
			b.WriteString(h.Alias)
		case 'r':
			b.WriteString(h.User)
		case 'p':
			b.WriteString(h.Port)
		default:
			b.WriteByte('%')
			b.WriteByte(s[i])
		}
	}
	return filepath.FromSlash(b.String())
}

// parseJump parses one ProxyJump element: [user@]host[:port].
func parseJump(s string) (user, host, port string, err error) {
	if i := strings.LastIndexByte(s, '@'); i >= 0 {
		user, s = s[:i], s[i+1:]
	}
	host, port, err = splitHostPortLoose(s)
	if err != nil {
		return "", "", "", err
	}
	if port != "" {
		if n, perr := strconv.ParseUint(port, 10, 16); perr != nil || n == 0 {
			return "", "", "", fmt.Errorf("invalid port %q", port)
		}
	}
	return user, host, port, nil
}

// splitHostPortLoose accepts "host", "host:port", "[v6]:port" and bare "v6".
func splitHostPortLoose(s string) (string, string, error) {
	if strings.HasPrefix(s, "[") {
		end := strings.IndexByte(s, ']')
		if end < 0 {
			return "", "", errors.New("missing ]")
		}
		host, rest := s[1:end], s[end+1:]
		if rest == "" {
			return host, "", nil
		}
		if !strings.HasPrefix(rest, ":") {
			return "", "", errors.New("junk after ]")
		}
		return host, rest[1:], nil
	}
	if strings.Count(s, ":") == 1 {
		h, p, _ := strings.Cut(s, ":")
		return h, p, nil
	}
	return s, "", nil
}
