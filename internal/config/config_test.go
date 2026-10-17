package config

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"
)

func write(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadAndMerge(t *testing.T) {
	f, err := Load(write(t, `
interval = "1s"
min_port = 2000
ignore = "5432"
quiet = true

[hosts.devbox]
interval = 3
ignore = [5432, 6379, "40000-50000"]
verbose = true

[hosts."db.example.com"]
only = "5432"
all_users = true
ignore_process = "^postgres$"

[hosts.web]
ignore_process = ["^node$", "\\.vscode-server"]
`), true)
	if err != nil {
		t.Fatal(err)
	}

	s := f.For("devbox")
	if s.Interval.Duration != 3*time.Second || *s.MinPort != 2000 || s.Ignore.Spec != "5432,6379,40000-50000" || !*s.Quiet || !*s.Verbose || s.Only != nil {
		t.Errorf("devbox: %+v", s)
	}
	s = f.For("db.example.com")
	if s.Only.Spec != "5432" || s.Ignore.Spec != "5432" || s.Interval.Duration != time.Second ||
		!*s.AllUsers || !slices.Equal(s.IgnoreProcess.Patterns, []string{"^postgres$"}) {
		t.Errorf("db: %+v", s)
	}
	if s = f.For("web"); !slices.Equal(s.IgnoreProcess.Patterns, []string{"^node$", `\.vscode-server`}) {
		t.Errorf("web: %+v", s.IgnoreProcess)
	}
	s = f.For("other")
	if s.Interval.Duration != time.Second || s.Verbose != nil || s.AllUsers != nil || s.IgnoreProcess != nil {
		t.Errorf("other: %+v", s)
	}
}

func TestLoadMissing(t *testing.T) {
	p := filepath.Join(t.TempDir(), "absent.toml")
	if _, err := Load(p, false); err != nil {
		t.Errorf("optional missing file: %v", err)
	}
	if _, err := Load(p, true); err == nil {
		t.Error("required missing file did not fail")
	}
}

func TestLoadRejectsUnknownKeys(t *testing.T) {
	_, err := Load(write(t, "intervall = \"2s\"\n[hosts.x]\nmin-port = 1\n"), true)
	if err == nil || !strings.Contains(err.Error(), "intervall") || !strings.Contains(err.Error(), "min-port") {
		t.Errorf("got %v", err)
	}
}

func TestLoadRejectsBadTypes(t *testing.T) {
	for _, body := range []string{`interval = "soon"`, `ignore = [true]`, `min_port = "x"`, `ignore_process = [1]`, `ignore_process = 3`, `all_users = "yes"`} {
		if _, err := Load(write(t, body), true); err == nil {
			t.Errorf("%s: no error", body)
		}
	}
}
