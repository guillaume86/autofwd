package ui

import (
	"bytes"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

// safeBuf is a goroutine-safe bytes.Buffer.
type safeBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *safeBuf) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *safeBuf) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// vtTerminal builds a Terminal that believes it drives a VT console.
func vtTerminal(w io.Writer, color bool) *Terminal {
	return &Terminal{w: w, fd: -1, vt: true, color: color, width: 100}
}

func TestPlainTerminalIsJustLines(t *testing.T) {
	var buf safeBuf
	tm := New(&buf, Options{}) // a bytes.Buffer is never a TTY
	if tm.Interactive() {
		t.Fatal("buffer reported as interactive")
	}
	tm.SetFooter([]string{"ignored"})
	tm.Line("12:00:00", "+ 3000  http://localhost:3000")
	if got := buf.String(); got != "12:00:00 + 3000  http://localhost:3000\n" {
		t.Errorf("plain output = %q", got)
	}
}

func TestFooterIsErasedBeforeEachLine(t *testing.T) {
	var buf safeBuf
	tm := vtTerminal(&buf, false)
	tm.SetFooter([]string{"row1", "row2"})
	tm.Line("12:00:00", "+ 3000  http://localhost:3000")
	tm.SetFooter(nil)
	got := buf.String()
	want := "row1\x1b[K\nrow2\x1b[K\n" + // initial draw
		"\r\x1b[2A\x1b[J" + // erase two footer lines
		"12:00:00 + 3000  http://localhost:3000\n" +
		"row1\x1b[K\nrow2\x1b[K\n" + // redraw
		"\r\x1b[2A\x1b[J" // hide
	if got != want {
		t.Errorf("sequence:\n got %q\nwant %q", got, want)
	}
	if tm.FooterShown() {
		t.Error("footer still shown after SetFooter(nil)")
	}
}

func TestColorsOnlyTheMarker(t *testing.T) {
	var buf safeBuf
	tm := vtTerminal(&buf, true)
	tm.Line("12:00:00", "+ 3000  http://localhost:3000")
	tm.Line("12:00:01", "! 8080 local port busy")
	tm.Line("12:00:02", "connected to dev")
	got := buf.String()
	for _, want := range []string{
		dim + "12:00:00" + reset + " " + green + "+ 3000" + reset + "  http://localhost:3000\n",
		red + "! 8080 local port busy" + reset + "\n",
		dim + "12:00:02" + reset + " connected to dev\n",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("output lacks %q:\n%q", want, got)
		}
	}
}

func TestKeysDropEscapeSequences(t *testing.T) {
	pr, pw := io.Pipe()
	in := newTestInput(pr)
	go func() {
		pw.Write([]byte("s"))
		pw.Write([]byte("\x1b[A")) // up arrow, in one read
		pw.Write([]byte("q"))
		pw.Close()
	}()
	var got []Key
	for k := range in.Keys() {
		got = append(got, k)
	}
	if string(got) != "sq" {
		t.Errorf("keys = %q, want \"sq\"", string(got))
	}
}

func TestPromptBorrowsTheKeyStream(t *testing.T) {
	pr, pw := io.Pipe()
	in := newTestInput(pr)
	var buf safeBuf
	tm := vtTerminal(&buf, false)
	tm.SetFooter([]string{"status"})
	p := Prompter{Term: tm, Input: in}

	type result struct {
		pass []byte
		err  error
	}
	res := make(chan result, 1)
	go func() {
		pass, err := p.Prompt("Passphrase: ")
		res <- result{pass, err}
	}()
	// Wait until the prompt has taken over before typing.
	deadline := time.Now().Add(2 * time.Second)
	for {
		in.mu.Lock()
		active := in.prompt != nil
		in.mu.Unlock()
		if active || time.Now().After(deadline) {
			break
		}
		time.Sleep(time.Millisecond)
	}
	pw.Write([]byte("secrex\x7ft\r"))
	r := <-res
	if r.err != nil || string(r.pass) != "secret" {
		t.Fatalf("prompt = %q, %v", r.pass, r.err)
	}
	if strings.Contains(buf.String(), "secret") {
		t.Error("passphrase was echoed")
	}
	if !tm.FooterShown() {
		t.Error("footer not restored after prompt")
	}
	// Keys flow to the handler again.
	pw.Write([]byte("v"))
	select {
	case k := <-in.Keys():
		if k != 'v' {
			t.Errorf("key after prompt = %q", k)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("no key after prompt")
	}
	pw.Close()
}

func TestPromptInterrupted(t *testing.T) {
	pr, pw := io.Pipe()
	in := newTestInput(pr)
	p := Prompter{Input: in}
	res := make(chan error, 1)
	go func() { _, err := p.Prompt("x: "); res <- err }()
	for {
		in.mu.Lock()
		active := in.prompt != nil
		in.mu.Unlock()
		if active {
			break
		}
		time.Sleep(time.Millisecond)
	}
	pw.Write([]byte{byte(CtrlC)})
	if err := <-res; err != ErrInterrupted {
		t.Errorf("err = %v, want ErrInterrupted", err)
	}
	pw.Close()
}
