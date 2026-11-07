package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/guillaume86/autofwd/internal/forward"
	"github.com/guillaume86/autofwd/internal/supervisor"
)

func TestExpandStatusPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home directory:", err)
	}
	for _, tt := range []struct{ tmpl, want string }{
		{"/run/autofwd/{pid}.json", filepath.Clean("/run/autofwd/4812.json")},
		{"/tmp/{host}-{pid}.json", filepath.Clean("/tmp/dev.box-4812.json")},
		{"~/.cache/autofwd/{host}.json", filepath.Join(home, ".cache", "autofwd", "dev.box.json")},
		{"~", home},
		{"status.json", "status.json"},
		{"~user/x.json", filepath.Clean("~user/x.json")}, // only a bare ~ means home
	} {
		got, err := expandStatusPath(tt.tmpl, "dev.box", 4812)
		if err != nil || got != tt.want {
			t.Errorf("expandStatusPath(%q) = %q, %v; want %q", tt.tmpl, got, err, tt.want)
		}
	}
	if got, _ := expandStatusPath("/tmp/{host}.json", "fe80::1%eth0", 1); got != filepath.Clean("/tmp/fe80__1_eth0.json") {
		t.Errorf("unsafe host characters: %q", got)
	}
	for _, tmpl := range []string{"", "/tmp/{port}.json", "/tmp/{PID}.json"} {
		if _, err := expandStatusPath(tmpl, "h", 1); err == nil {
			t.Errorf("expandStatusPath(%q): no error", tmpl)
		}
	}
}

func TestStatusUsageErrors(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "empty.toml")
	os.WriteFile(cfg, nil, 0o600)
	for _, args := range [][]string{
		{"--config", cfg, "--status-file", "", "host"},
		{"--config", cfg, "--status-file", "/tmp/{nope}.json", "host"},
	} {
		var out bytes.Buffer
		if code := run(args, &out, &out); code != 2 || !strings.Contains(out.String(), "--status-file") {
			t.Errorf("run(%q) = %d; output:\n%s", args, code, out.String())
		}
	}
}

func testStatus(now time.Time) supervisor.Status {
	return supervisor.Status{
		Dest:          "me@devbox",
		State:         supervisor.Connected,
		Since:         now.Add(-time.Hour),
		LastKeepalive: now.Add(-10 * time.Second),
		Forwards: []forward.PortStatus{{
			Port: 3000, Target: netip.MustParseAddrPort("127.0.0.1:3000"),
			Remote: forward.Remote{Label: "node  ~/src/app", Process: "node", Dir: "~/src/app"},
			Since:  now.Add(-time.Minute), Conns: 2,
		}, {
			Port: 5432, Target: netip.MustParseAddrPort("127.0.0.1:5432"),
			Remote: forward.Remote{Label: "docker-proxy  db", Process: "docker-proxy", Container: "db",
				ContainerAddr: netip.MustParseAddrPort("172.17.0.2:5432")},
			Since: now.Add(-time.Minute),
		}},
		Busy:    []forward.BusyStatus{{Port: 9229, Reason: "local port busy", RetryAt: now.Add(30 * time.Second)}},
		Skipped: []supervisor.Skipped{{Port: 45747, Reason: "owned by root", Process: "containerd"}},
	}
}

func readStatus(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, b)
	}
	return m
}

func TestStatusFileContent(t *testing.T) {
	now := time.Date(2026, 11, 6, 12, 0, 0, 123456789, time.FixedZone("CET", 3600))
	path := filepath.Join(t.TempDir(), "nested", "4812.json")
	f, err := newStatusFile(path, "me@devbox", 4812, now.Add(-2*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if err := f.write(f.doc(testStatus(now))); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	var got statusDoc
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	keepalive := "2026-11-06T10:59:50.123Z"
	want := statusDoc{
		Format: 1, Version: versionString(), PID: 4812, Host: "me@devbox",
		Started: "2026-11-06T09:00:00.123Z", State: "connected", Since: "2026-11-06T10:00:00.123Z",
		LastKeepalive: &keepalive,
		Forwards: []statusForward{{Port: 3000, URL: "http://localhost:3000", Remote: "127.0.0.1:3000",
			Process: "node", Dir: "~/src/app", Since: "2026-11-06T10:59:00.123Z", Conns: 2},
			{Port: 5432, URL: "http://localhost:5432", Remote: "127.0.0.1:5432", Process: "docker-proxy",
				Container: "db", ContainerAddr: "172.17.0.2:5432", Since: "2026-11-06T10:59:00.123Z"}},
		Busy:    []statusBusy{{Port: 9229, Reason: "local port busy", RetryAt: "2026-11-06T11:00:30.123Z"}},
		Skipped: []statusSkipped{{Port: 45747, Reason: "owned by root", Process: "containerd"}},
	}
	gotJSON, _ := json.Marshal(got)
	wantJSON, _ := json.Marshal(want)
	if !bytes.Equal(gotJSON, wantJSON) {
		t.Errorf("status file\n got %s\nwant %s", gotJSON, wantJSON)
	}

	// Optional values are null, lists are never null.
	m := readStatus(t, path)
	if m["retry_at"] != nil {
		t.Errorf("retry_at = %v while connected", m["retry_at"])
	}
	empty := f.doc(supervisor.Status{Dest: "devbox", State: supervisor.Waiting, Since: now, RetryAt: now.Add(4 * time.Second), LastError: "dial tcp: timeout"})
	if empty.Forwards == nil || empty.Busy == nil || empty.Skipped == nil || empty.LastKeepalive != nil {
		t.Errorf("empty lists or keepalive: %+v", empty)
	}
	if empty.State != "reconnecting" || empty.RetryAt == nil || *empty.RetryAt != "2026-11-06T11:00:04.123Z" || empty.Error != "dial tcp: timeout" {
		t.Errorf("reconnecting doc: %+v", empty)
	}
}

func TestStatusFileWritesOnlyChanges(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	f, _ := newStatusFile(path, "devbox", 1, time.Now())
	st := testStatus(time.Now())
	if err := f.write(f.doc(st)); err != nil {
		t.Fatal(err)
	}
	// Something else replaces the file: an unchanged state does not rewrite it.
	os.WriteFile(path, []byte("{}"), 0o644)
	f.write(f.doc(st))
	if b, _ := os.ReadFile(path); string(b) != "{}" {
		t.Errorf("unchanged state rewrote the file")
	}
	st.Forwards[0].Conns++
	f.write(f.doc(st))
	if m := readStatus(t, path); m["pid"] != float64(1) {
		t.Errorf("changed state not written: %v", m)
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Errorf("temporary files left behind: %v", entries)
	}
}

func TestStatusFileFinish(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "s.json")
	f, _ := newStatusFile(path, "devbox", 1, time.Now())
	f.write(f.doc(testStatus(time.Now())))

	// A fatal error stays on record.
	if err := f.finish(supervisor.Status{Dest: "devbox", State: supervisor.Waiting, RetryAt: time.Now()}, errors.New("host key mismatch")); err != nil {
		t.Fatal(err)
	}
	m := readStatus(t, path)
	if m["state"] != "failed" || m["error"] != "host key mismatch" || m["retry_at"] != nil {
		t.Errorf("after a fatal error: %v", m)
	}

	// A clean exit removes the file, and removing it twice is fine.
	if err := f.finish(supervisor.Status{}, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Errorf("file still there after a clean exit: %v", err)
	}
	if err := f.finish(supervisor.Status{}, nil); err != nil {
		t.Errorf("second clean finish: %v", err)
	}
}
