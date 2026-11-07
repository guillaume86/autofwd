package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/guillaume86/autofwd/internal/forward"
	"github.com/guillaume86/autofwd/internal/logx"
	"github.com/guillaume86/autofwd/internal/supervisor"
)

// The status file (--status-file) is a JSON snapshot of what the status
// footer shows, for programs that display autofwd's state elsewhere. It is
// rewritten whenever the state changes, through a temporary file and a
// rename, so a reader never sees half of it. A clean exit removes it; a
// fatal error leaves it behind with state "failed" and the reason.

// statusFormat is bumped on incompatible changes to statusDoc.
const statusFormat = 1

// statusInterval is how often the state is compared with the file.
const statusInterval = 500 * time.Millisecond

// statusDoc is the file's content. Times are RFC 3339 in UTC with
// milliseconds; optional ones are null when they don't apply.
type statusDoc struct {
	Format        int             `json:"format"`
	Version       string          `json:"version"` // autofwd's
	PID           int             `json:"pid"`
	Host          string          `json:"host"` // as given on the command line
	Started       string          `json:"started"`
	State         string          `json:"state"` // connecting, connected, reconnecting or failed
	Since         string          `json:"since"` // when State began
	RetryAt       *string         `json:"retry_at"`
	Error         string          `json:"error"` // why the last attempt or connection ended, or why autofwd stopped
	LastKeepalive *string         `json:"last_keepalive"`
	Forwards      []statusForward `json:"forwards"`
	Busy          []statusBusy    `json:"busy"`
	Skipped       []statusSkipped `json:"skipped"`
}

type statusForward struct {
	Port    uint16 `json:"port"`
	URL     string `json:"url"`
	Remote  string `json:"remote"`  // the address dialed on the remote side
	Process string `json:"process"` // the remote process or systemd unit, when known
	Dir     string `json:"dir"`     // its working directory, home as ~, when known
	// The Docker container behind a docker-proxy: its name, when docker ps
	// could tell, and its address.
	Container     string `json:"container"`
	ContainerAddr string `json:"container_addr"`
	Since         string `json:"since"`
	Conns         int    `json:"conns"` // proxied connections open now
}

type statusBusy struct {
	Port    uint16 `json:"port"`
	Reason  string `json:"reason"`
	RetryAt string `json:"retry_at"`
}

type statusSkipped struct {
	Port    uint16 `json:"port"`
	Reason  string `json:"reason"`
	Process string `json:"process"`
}

func isoTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }

func isoTimePtr(t time.Time) *string {
	if t.IsZero() {
		return nil
	}
	s := isoTime(t)
	return &s
}

// statusFile writes the snapshots, skipping those that match the last one
// written.
type statusFile struct {
	path    string
	host    string
	pid     int
	started time.Time
	last    []byte
	lastErr string // the last write error logged, so a stuck file warns once
}

// placeholder matches {name} in a --status-file path.
var placeholder = regexp.MustCompile(`\{[^{}/\\]*\}`)

// expandStatusPath resolves a --status-file value: {pid} becomes autofwd's
// process ID, {host} the host alias (characters unsafe in file names
// replaced by _), and a leading ~ the home directory, for callers that start
// autofwd without a shell.
func expandStatusPath(tmpl, alias string, pid int) (string, error) {
	if tmpl == "" {
		return "", fmt.Errorf("empty path")
	}
	var bad string
	path := placeholder.ReplaceAllStringFunc(tmpl, func(m string) string {
		switch m {
		case "{pid}":
			return strconv.Itoa(pid)
		case "{host}":
			return safeName(alias)
		}
		if bad == "" {
			bad = m
		}
		return m
	})
	if bad != "" {
		return "", fmt.Errorf("unknown placeholder %s (known: {pid}, {host})", bad)
	}
	if path == "~" || strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("expanding ~: %w", err)
		}
		path = filepath.Join(home, path[1:])
	}
	return filepath.Clean(path), nil
}

// safeName keeps letters, digits, '.', '-' and '_', and replaces the rest.
func safeName(s string) string {
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			return r
		}
		return '_'
	}, s)
}

func newStatusFile(path, host string, pid int, started time.Time) (*statusFile, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	return &statusFile{path: path, host: host, pid: pid, started: started}, nil
}

// doc turns a supervisor snapshot into the file's content.
func (f *statusFile) doc(st supervisor.Status) statusDoc {
	d := statusDoc{
		Format:        statusFormat,
		Version:       versionString(),
		PID:           f.pid,
		Host:          f.host,
		Started:       isoTime(f.started),
		State:         st.State.String(),
		Since:         isoTime(st.Since),
		Error:         st.LastError,
		LastKeepalive: isoTimePtr(st.LastKeepalive),
		Forwards:      []statusForward{},
		Busy:          []statusBusy{},
		Skipped:       []statusSkipped{},
	}
	if st.State == supervisor.Waiting {
		d.RetryAt = isoTimePtr(st.RetryAt)
	}
	if st.State != supervisor.Connected {
		d.LastKeepalive = nil
	}
	for _, p := range st.Forwards {
		f := statusForward{
			Port: p.Port, URL: forward.LocalURL(p.Port), Remote: p.Target.String(),
			Process: p.Process, Dir: p.Dir, Container: p.Container, Since: isoTime(p.Since), Conns: p.Conns,
		}
		if p.ContainerAddr.IsValid() {
			f.ContainerAddr = p.ContainerAddr.String()
		}
		d.Forwards = append(d.Forwards, f)
	}
	for _, b := range st.Busy {
		d.Busy = append(d.Busy, statusBusy{Port: b.Port, Reason: b.Reason, RetryAt: isoTime(b.RetryAt)})
	}
	for _, s := range st.Skipped {
		d.Skipped = append(d.Skipped, statusSkipped{Port: s.Port, Reason: s.Reason, Process: s.Process})
	}
	return d
}

// write replaces the file with d, unless that is what it already holds.
func (f *statusFile) write(d statusDoc) error {
	b, err := json.MarshalIndent(d, "", "  ")
	if err != nil {
		return err
	}
	b = append(b, '\n')
	if bytes.Equal(b, f.last) {
		return nil
	}
	if err := writeAtomic(f.path, b); err != nil {
		return err
	}
	f.last = b
	return nil
}

// writeAtomic writes b to a temporary file beside path, then renames it over
// path. The temporary name ends in .tmp, so watchers can ignore it.
func writeAtomic(path string, b []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	_, err = tmp.Write(b)
	if cerr := tmp.Close(); err == nil {
		err = cerr
	}
	if err == nil {
		// On Windows a reader holding the file open without sharing delete
		// access makes this fail; the next tick tries again.
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}

// update writes the supervisor's current state, logging a failure once
// until a write succeeds again.
func (f *statusFile) update(st supervisor.Status, log *logx.Logger) {
	if err := f.write(f.doc(st)); err != nil {
		if msg := err.Error(); msg != f.lastErr {
			f.lastErr = msg
			log.Warnf("! status file: %v", err)
		}
		return
	}
	f.lastErr = ""
}

// runStatusFile keeps the file in step with sup until ctx ends, then closes
// the returned channel. It writes the first snapshot before returning.
func runStatusFile(ctx context.Context, f *statusFile, sup *supervisor.Supervisor, log *logx.Logger) <-chan struct{} {
	done := make(chan struct{})
	f.update(sup.Status(), log)
	go func() {
		defer close(done)
		t := time.NewTicker(statusInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				f.update(sup.Status(), log)
			}
		}
	}()
	return done
}

// finish ends the file's life with autofwd's: removed after a clean exit,
// kept with state "failed" after a fatal error.
func (f *statusFile) finish(st supervisor.Status, runErr error) error {
	if runErr == nil {
		err := os.Remove(f.path)
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	d := f.doc(st)
	d.State, d.Since, d.Error, d.RetryAt = "failed", isoTime(time.Now()), runErr.Error(), nil
	return f.write(d)
}
