package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/guillaume86/autofwd/internal/ports"
)

func TestUsageErrors(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "empty.toml")
	os.WriteFile(cfg, nil, 0o600)
	for _, args := range [][]string{
		{},
		{"a", "b"},
		{"--config", cfg, "--quiet", "--verbose", "host"},
		{"--config", cfg, "--ignore", "abc", "host"},
		{"--config", cfg, "--only", "1-0", "host"},
		{"--config", cfg, "--interval", "1ms", "host"},
		{"--config", cfg, "--min-port", "70000", "host"},
		{"--config", cfg, "--ignore-process", "(unclosed", "host"},
		{"--nope", "host"},
		{"--config", filepath.Join(t.TempDir(), "missing.toml"), "host"},
	} {
		var out bytes.Buffer
		if code := run(args, &out, &out); code != 2 {
			t.Errorf("run(%q) = %d, want 2; output:\n%s", args, code, out.String())
		}
	}
}

func TestVersion(t *testing.T) {
	var out bytes.Buffer
	if code := run([]string{"--version"}, &out, &out); code != 0 || !strings.Contains(out.String(), "autofwd") {
		t.Errorf("--version: %d %q", code, out.String())
	}
}

func TestApplyConfig(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(cfg, []byte(`
interval = "5s"
min_port = 3000
quiet = true
[hosts.devbox]
ignore = [5432, "40000-50000"]
`), 0o600)

	// Nothing on the command line: the file wins.
	o := options{interval: 2 * time.Second, minPort: 1024, configPath: cfg}
	if err := applyConfig(&o, map[string]bool{}, "devbox"); err != nil {
		t.Fatal(err)
	}
	if o.interval != 5*time.Second || o.minPort != 3000 || o.ignore != "5432,40000-50000" || !o.quiet {
		t.Errorf("from file: %+v", o)
	}

	// Explicit flags beat the file, and -v cancels a configured quiet.
	o = options{interval: time.Second, minPort: 1024, ignore: "1", verbose: true, configPath: cfg}
	if err := applyConfig(&o, map[string]bool{"interval": true, "min-port": true, "ignore": true, "v": true}, "devbox"); err != nil {
		t.Fatal(err)
	}
	if o.interval != time.Second || o.minPort != 1024 || o.ignore != "1" || o.quiet || !o.verbose {
		t.Errorf("flags over file: %+v", o)
	}
}

func TestIgnoreProcessPrecedence(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "config.toml")
	os.WriteFile(cfg, []byte("all_users = true\n[hosts.devbox]\nignore_process = [\"^bun$\"]\n"), 0o600)

	// Defaults when nothing sets it.
	var o options
	o.ignoreProcess.list = slices.Clone(ports.DefaultIgnoreProcess)
	o.configPath = cfg
	if err := applyConfig(&o, map[string]bool{}, "other"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.ignoreProcess.list, ports.DefaultIgnoreProcess) || !o.allUsers {
		t.Errorf("defaults: %+v", o)
	}

	// The config file replaces the defaults.
	o.ignoreProcess.list = slices.Clone(ports.DefaultIgnoreProcess)
	if err := applyConfig(&o, map[string]bool{}, "devbox"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.ignoreProcess.list, []string{"^bun$"}) {
		t.Errorf("from file: %q", o.ignoreProcess.list)
	}

	// Flags replace both; repeating appends; an empty value clears.
	p := patternsFlag{list: slices.Clone(ports.DefaultIgnoreProcess)}
	for _, v := range []string{"^a$", "^b$"} {
		if err := p.Set(v); err != nil {
			t.Fatal(err)
		}
	}
	if !slices.Equal(p.list, []string{"^a$", "^b$"}) {
		t.Errorf("repeated flag: %q", p.list)
	}
	o = options{ignoreProcess: p, configPath: cfg}
	if err := applyConfig(&o, map[string]bool{"ignore-process": true}, "devbox"); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(o.ignoreProcess.list, []string{"^a$", "^b$"}) {
		t.Errorf("flag over file: %q", o.ignoreProcess.list)
	}
	if err := p.Set(""); err != nil || len(p.list) != 0 {
		t.Errorf("empty value: %q, %v", p.list, err)
	}
}

func TestHelpAndUsageErrorsStreams(t *testing.T) {
	var out, errb bytes.Buffer
	if code := run([]string{"--help"}, &out, &errb); code != 0 || !strings.Contains(out.String(), "Usage: autofwd") || errb.Len() != 0 {
		t.Errorf("--help: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	out.Reset()
	errb.Reset()
	if code := run(nil, &out, &errb); code != 2 || !strings.Contains(errb.String(), "missing host") || out.Len() != 0 {
		t.Errorf("no args: code %d stdout %q stderr %q", code, out.String(), errb.String())
	}
	errb.Reset()
	if code := run([]string{"bob@"}, &out, &errb); code != 2 || !strings.Contains(errb.String(), "invalid host") {
		t.Errorf("bob@: code %d stderr %q", code, errb.String())
	}
}

func TestDurationFlag(t *testing.T) {
	for in, want := range map[string]time.Duration{"5": 5 * time.Second, "0.5": 500 * time.Millisecond, "250ms": 250 * time.Millisecond, "1m": time.Minute} {
		var d time.Duration
		if err := (durationFlag{&d}).Set(in); err != nil || d != want {
			t.Errorf("Set(%q) = %v, %v; want %v", in, d, err, want)
		}
	}
	var d time.Duration
	if err := (durationFlag{&d}).Set("fast"); err == nil {
		t.Error("Set(fast) accepted")
	}
}
