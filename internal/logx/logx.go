// Package logx is a minimal leveled logger that prints one line per event.
package logx

import (
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// Level selects how much is printed.
type Level int

const (
	Quiet   Level = iota // warnings and errors only
	Normal               // plus forward and connection events
	Verbose              // plus per-connection and diagnostic detail
)

// Sink receives formatted lines. An io.Writer that also implements Sink
// (such as the interactive terminal) gets the timestamp and message
// separately so it can color them and keep its footer below.
type Sink interface {
	Line(ts, msg string)
}

// Logger writes timestamped lines. It is safe for concurrent use; a nil
// *Logger discards everything.
type Logger struct {
	mu    sync.Mutex
	w     io.Writer
	sink  Sink // non-nil when w implements Sink
	level atomic.Int32
	now   func() time.Time
}

func New(w io.Writer, level Level) *Logger {
	l := &Logger{w: w, now: time.Now}
	l.sink, _ = w.(Sink)
	l.level.Store(int32(level))
	return l
}

// Level returns the current verbosity.
func (l *Logger) Level() Level { return Level(l.level.Load()) }

// SetLevel changes the verbosity at runtime.
func (l *Logger) SetLevel(level Level) { l.level.Store(int32(level)) }

func (l *Logger) printf(min Level, format string, args ...any) {
	if l == nil || l.Level() < min {
		return
	}
	ts, msg := l.now().Format("15:04:05"), fmt.Sprintf(format, args...)
	if l.sink != nil {
		l.sink.Line(ts, msg)
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.w, "%s %s\n", ts, msg)
}

// Warnf logs a problem; it is shown even in quiet mode.
func (l *Logger) Warnf(format string, args ...any) { l.printf(Quiet, format, args...) }

// Statef logs a connection state change. Like warnings it is shown in quiet
// mode, so a long-running quiet autofwd still says when it reconnects.
func (l *Logger) Statef(format string, args ...any) { l.printf(Quiet, format, args...) }

// Infof logs a normal event such as a forward appearing.
func (l *Logger) Infof(format string, args ...any) { l.printf(Normal, format, args...) }

// Debugf logs detail that is only interesting with --verbose.
func (l *Logger) Debugf(format string, args ...any) { l.printf(Verbose, format, args...) }

// Enabled reports whether messages at level would be printed.
func (l *Logger) Enabled(level Level) bool { return l != nil && l.Level() >= level }
