// Package config reads autofwd's optional TOML file of per-host defaults.
//
//	# top level: defaults for every host
//	interval = "2s"
//	min_port = 1024
//	ignore   = "5432,6379"
//
//	[hosts.devbox]          # the alias given on the command line
//	ignore = [5432, 6379, "40000-50000"]
//	only   = "3000-3999"
package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
)

// Settings holds every flag a config file may set. nil means "not set".
type Settings struct {
	Interval *Duration `toml:"interval"`
	MinPort  *int      `toml:"min_port"`
	Ignore   *PortList `toml:"ignore"`
	Only     *PortList `toml:"only"`
	Quiet    *bool     `toml:"quiet"`
	Verbose  *bool     `toml:"verbose"`
}

type File struct {
	Settings
	Hosts map[string]Settings `toml:"hosts"`
}

// For returns the effective settings for alias: host table over top level.
func (f *File) For(alias string) Settings {
	s := f.Settings
	h, ok := f.Hosts[alias]
	if !ok {
		return s
	}
	if h.Interval != nil {
		s.Interval = h.Interval
	}
	if h.MinPort != nil {
		s.MinPort = h.MinPort
	}
	if h.Ignore != nil {
		s.Ignore = h.Ignore
	}
	if h.Only != nil {
		s.Only = h.Only
	}
	if h.Quiet != nil {
		s.Quiet = h.Quiet
	}
	if h.Verbose != nil {
		s.Verbose = h.Verbose
	}
	return s
}

// DefaultPath is %APPDATA%\autofwd\config.toml on Windows and
// $XDG_CONFIG_HOME/autofwd/config.toml (default ~/.config) elsewhere,
// macOS included, as is usual for command-line tools.
func DefaultPath() string {
	if runtime.GOOS == "windows" {
		if d := os.Getenv("APPDATA"); d != "" {
			return filepath.Join(d, "autofwd", "config.toml")
		}
	}
	if d := os.Getenv("XDG_CONFIG_HOME"); d != "" {
		return filepath.Join(d, "autofwd", "config.toml")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(home, ".config", "autofwd", "config.toml")
}

// Load parses path. A missing file is an empty config unless required.
func Load(path string, required bool) (*File, error) {
	f := &File{}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) && !required {
		return f, nil
	}
	if err != nil {
		return nil, err
	}
	md, err := toml.Decode(string(data), f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if extra := md.Undecoded(); len(extra) > 0 {
		keys := make([]string, len(extra))
		for i, k := range extra {
			keys[i] = k.String()
		}
		return nil, fmt.Errorf("%s: unknown keys: %s", path, strings.Join(keys, ", "))
	}
	return f, nil
}

// Duration accepts "2s", "500ms" or a plain number of seconds.
type Duration struct{ time.Duration }

func (d *Duration) UnmarshalTOML(v any) error {
	switch x := v.(type) {
	case string:
		dur, err := time.ParseDuration(x)
		if err != nil {
			return err
		}
		d.Duration = dur
	case int64:
		d.Duration = time.Duration(x) * time.Second
	case float64:
		d.Duration = time.Duration(x * float64(time.Second))
	default:
		return fmt.Errorf("want a duration like \"2s\", got %T", v)
	}
	return nil
}

// PortList accepts "5432,40000-50000" or an array of ports and "lo-hi"
// strings. It is kept as text and parsed together with the CLI flags.
type PortList struct{ Spec string }

func (p *PortList) UnmarshalTOML(v any) error {
	switch x := v.(type) {
	case string:
		p.Spec = x
	case int64:
		p.Spec = fmt.Sprint(x)
	case []any:
		parts := make([]string, 0, len(x))
		for _, e := range x {
			switch y := e.(type) {
			case string:
				parts = append(parts, y)
			case int64:
				parts = append(parts, fmt.Sprint(y))
			default:
				return fmt.Errorf("port list entries must be numbers or strings, got %T", e)
			}
		}
		p.Spec = strings.Join(parts, ",")
	default:
		return fmt.Errorf("want a port list, got %T", v)
	}
	return nil
}
