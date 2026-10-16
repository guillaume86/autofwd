package ui

import (
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/term"
)

// Prompter asks the user for a secret on the terminal. With an Input in raw
// mode it reads through that Input, so the key handler and the prompt never
// fight over stdin; without one it falls back to term.ReadPassword.
type Prompter struct {
	Term  *Terminal
	Input *Input
}

// Prompt prints prompt and reads a line without echo. The footer is hidden
// while the prompt is on screen.
func (p Prompter) Prompt(prompt string) ([]byte, error) {
	var footer []string
	if p.Term != nil {
		p.Term.mu.Lock()
		footer = p.Term.footer
		p.Term.mu.Unlock()
		p.Term.SetFooter(nil)
		defer p.Term.SetFooter(footer)
	}
	out := io.Writer(os.Stderr)
	if p.Term != nil {
		out = p.Term
	}

	if p.Input == nil {
		fd := int(os.Stdin.Fd())
		if !term.IsTerminal(fd) {
			return nil, errors.New("stdin is not a terminal, cannot ask for a passphrase (load the key into ssh-agent instead)")
		}
		fmt.Fprint(out, prompt)
		defer fmt.Fprintln(out)
		return term.ReadPassword(fd)
	}

	keys, release := p.Input.borrow()
	defer release()
	fmt.Fprint(out, prompt)
	defer fmt.Fprintln(out)
	var line []byte
	for k := range keys {
		switch k {
		case Enter, '\n':
			return line, nil
		case CtrlC:
			return nil, ErrInterrupted
		case CtrlD:
			if len(line) == 0 {
				return nil, io.EOF
			}
		case 0x7f, 0x08: // backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
			}
		case 0x15: // Ctrl+U clears the line
			line = line[:0]
		default:
			if k >= 0x20 {
				line = append(line, byte(k))
			}
		}
	}
	return nil, io.EOF
}
