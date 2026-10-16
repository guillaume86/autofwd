package ui

import (
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/term"
)

// Key is one keypress. Escape sequences (arrows, function keys) are dropped,
// so a Key is always a single byte: a printable character or a control code
// such as CtrlC.
type Key byte

const (
	CtrlC Key = 0x03
	CtrlD Key = 0x04
	Enter Key = '\r'
	Esc   Key = 0x1b
)

// Input owns stdin in raw mode and hands keys to one consumer at a time:
// normally the key handler, but a Prompt borrows the stream while it runs.
type Input struct {
	keys    chan Key
	restore func()

	mu     sync.Mutex
	prompt chan Key // non-nil while a prompt is reading
}

// OpenInput switches r (normally os.Stdin) to raw mode and starts reading
// keys. It returns nil when r is not a terminal, in which case there are no
// keys and Prompt falls back to term.ReadPassword semantics.
func OpenInput(r io.Reader) *Input {
	f, ok := r.(*os.File)
	if !ok || !term.IsTerminal(int(f.Fd())) {
		return nil
	}
	fd := int(f.Fd())
	st, err := term.MakeRaw(fd)
	if err != nil {
		return nil
	}
	in := &Input{
		keys:    make(chan Key, 16),
		restore: func() { term.Restore(fd, st) },
	}
	go in.read(f)
	return in
}

// newTestInput reads keys from any reader without touching terminal modes.
func newTestInput(r io.Reader) *Input {
	in := &Input{keys: make(chan Key, 16), restore: func() {}}
	go in.read(r)
	return in
}

func (in *Input) read(r io.Reader) {
	defer close(in.keys)
	buf := make([]byte, 64)
	for {
		n, err := r.Read(buf)
		for i := 0; i < n; i++ {
			b := buf[i]
			if b == byte(Esc) {
				// Drop the rest of an escape sequence: ESC [ ... final byte
				// in 0x40-0x7e, or ESC O x. Anything left in this read is
				// assumed to belong to it.
				i = n
				continue
			}
			in.deliver(Key(b))
		}
		if err != nil {
			return
		}
	}
}

func (in *Input) deliver(k Key) {
	in.mu.Lock()
	p := in.prompt
	in.mu.Unlock()
	if p != nil {
		p <- k
		return
	}
	select {
	case in.keys <- k:
	default: // nobody is reading fast enough; dropping keys is fine
	}
}

// Keys is the stream of keypresses not consumed by a prompt. It is closed
// when stdin hits EOF.
func (in *Input) Keys() <-chan Key {
	if in == nil {
		return nil
	}
	return in.keys
}

// Close restores the terminal mode. Call it on every exit path.
func (in *Input) Close() {
	if in != nil {
		in.restore()
	}
}

// ErrInterrupted is returned by Prompt when the user presses Ctrl+C.
var ErrInterrupted = errors.New("interrupted")

// borrow routes keys to a prompt until the returned func is called.
func (in *Input) borrow() (<-chan Key, func()) {
	ch := make(chan Key, 16)
	in.mu.Lock()
	in.prompt = ch
	in.mu.Unlock()
	return ch, func() {
		in.mu.Lock()
		in.prompt = nil
		in.mu.Unlock()
	}
}
