// Package ui is the interactive terminal layer: a colored log sink with a
// hideable status footer, a raw-mode key reader, and a passphrase prompt
// that shares stdin with it. Everything degrades to plain output when the
// terminal is not interactive.
package ui

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"golang.org/x/term"
)

// Terminal writes log lines and, when shown, a status footer that stays
// below the scrolling log. It is safe for concurrent use.
type Terminal struct {
	mu     sync.Mutex
	w      io.Writer
	fd     int  // stderr fd for size queries; -1 when unknown
	vt     bool // escape sequences understood
	color  bool
	footer []string // current footer content; nil when hidden
	drawn  int      // lines the footer currently occupies on screen
	width  int      // last known width, for tests and for narrowing
}

// Options for New. Zero values mean "detect".
type Options struct {
	// Plain disables colors, the footer and VT output regardless of TTY.
	Plain bool
	// NoColor disables colors only (set from NO_COLOR or TERM=dumb).
	NoColor bool
}

// New wraps w, which is normally os.Stderr. If w is a terminal, VT output is
// enabled (on Windows through the console mode) and colors are on unless
// disabled.
func New(w io.Writer, opts Options) *Terminal {
	t := &Terminal{w: w, fd: -1, width: 80}
	f, ok := w.(*os.File)
	if !ok || opts.Plain || !term.IsTerminal(int(f.Fd())) {
		return t
	}
	t.fd = int(f.Fd())
	if !enableVT(f) {
		return t
	}
	t.vt = true
	t.color = !opts.NoColor && os.Getenv("NO_COLOR") == "" && os.Getenv("TERM") != "dumb"
	if wd, _, err := term.GetSize(t.fd); err == nil && wd > 0 {
		t.width = wd
	}
	return t
}

// Interactive reports whether the footer can be shown.
func (t *Terminal) Interactive() bool { return t.vt }

// Width returns the terminal width, re-queried each call.
func (t *Terminal) Width() int {
	if t.fd >= 0 {
		if wd, _, err := term.GetSize(t.fd); err == nil && wd > 0 {
			t.width = wd
		}
	}
	return t.width
}

// Line writes one log line, keeping the footer (if shown) below it. The
// first rune of msg selects the color: + green, - yellow, ! red, ~ cyan.
func (t *Terminal) Line(ts, msg string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.eraseFooterLocked()
	if !t.color {
		fmt.Fprintf(t.w, "%s %s\n", ts, msg)
	} else {
		fmt.Fprintf(t.w, "%s%s%s %s\n", dim, ts, reset, colorize(msg))
	}
	t.drawFooterLocked()
}

// SetFooter replaces the footer. nil hides it.
func (t *Terminal) SetFooter(lines []string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.vt {
		return
	}
	t.eraseFooterLocked()
	t.footer = lines
	t.drawFooterLocked()
}

// FooterShown reports whether a footer is currently displayed.
func (t *Terminal) FooterShown() bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.footer != nil
}

// Close erases the footer so it does not linger after exit.
func (t *Terminal) Close() {
	t.SetFooter(nil)
}

// Write lets the Terminal stand in for a plain io.Writer (prompts, usage).
func (t *Terminal) Write(p []byte) (int, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.eraseFooterLocked()
	n, err := t.w.Write(p)
	t.drawFooterLocked()
	return n, err
}

const (
	reset  = "\x1b[0m"
	dim    = "\x1b[2m"
	red    = "\x1b[31m"
	green  = "\x1b[32m"
	yellow = "\x1b[33m"
	cyan   = "\x1b[36m"
	bold   = "\x1b[1m"
)

func colorize(msg string) string {
	if msg == "" {
		return msg
	}
	var c string
	switch msg[0] {
	case '+':
		c = green
	case '-':
		c = yellow
	case '!':
		c = red
	case '~':
		c = cyan
	default:
		return msg
	}
	// Color the marker and the port that follows it, leave the rest plain so
	// URLs stay easy to read and click.
	head, rest, _ := strings.Cut(msg, "  ")
	if rest == "" {
		return c + msg + reset
	}
	return c + head + reset + "  " + rest
}

// eraseFooterLocked moves the cursor back over the drawn footer and clears
// to the end of the screen.
func (t *Terminal) eraseFooterLocked() {
	if t.drawn == 0 {
		return
	}
	fmt.Fprintf(t.w, "\r\x1b[%dA\x1b[J", t.drawn)
	t.drawn = 0
}

func (t *Terminal) drawFooterLocked() {
	if t.footer == nil || !t.vt {
		return
	}
	var b strings.Builder
	for _, l := range t.footer {
		b.WriteString(l)
		b.WriteString("\x1b[K\n")
	}
	io.WriteString(t.w, b.String())
	t.drawn = len(t.footer)
}
