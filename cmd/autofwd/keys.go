package main

import (
	"context"
	"os"
	"sync/atomic"
	"time"

	"github.com/guillaume86/autofwd/internal/forward"
	"github.com/guillaume86/autofwd/internal/logx"
	"github.com/guillaume86/autofwd/internal/supervisor"
	"github.com/guillaume86/autofwd/internal/ui"
)

const keyHelp = "keys: s status  v verbose  o open newest  1-9 open row  r poll now  q quit"

// runKeys handles keypresses and the status footer until ctx ends. It
// returns immediately when there is no interactive input.
func runKeys(ctx context.Context, cancel context.CancelFunc, term *ui.Terminal, input *ui.Input, sup *supervisor.Supervisor, log *logx.Logger) {
	if input == nil || !term.Interactive() {
		return
	}
	log.Infof("press s for status, ? for keys")

	var shown atomic.Bool
	refresh := make(chan struct{}, 1)
	kick := func() {
		select {
		case refresh <- struct{}{}:
		default:
		}
	}

	// The footer redraws every second while shown (ages, countdowns) and
	// right away on toggle.
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			case <-refresh:
			}
			if shown.Load() {
				term.SetFooter(formatStatus(sup.Status(), term.Width(), time.Now()))
			} else {
				term.SetFooter(nil)
			}
		}
	}()

	open := func(port uint16) {
		url := forward.LocalURL(port)
		if err := ui.OpenURL(url); err != nil {
			log.Warnf("! cannot open %s: %v", url, err)
			return
		}
		log.Infof("~ opened %s", url)
	}

	go func() {
		for k := range input.Keys() {
			switch k {
			case 'q', ui.CtrlC, ui.CtrlD:
				if ctx.Err() != nil {
					// Second press while shutting down: leave now, but
					// with the terminal restored.
					input.Close()
					term.Close()
					os.Exit(130)
				}
				cancel()
			case 's', ' ':
				shown.Store(!shown.Load())
				kick()
			case 'v':
				if log.Level() == logx.Verbose {
					log.SetLevel(logx.Normal)
					log.Infof("~ verbose off")
				} else {
					log.SetLevel(logx.Verbose)
					log.Infof("~ verbose on")
				}
			case 'r':
				sup.Poke()
				log.Infof("~ polling now, retrying busy ports")
			case 'o':
				st := sup.Status()
				if len(st.Forwards) == 0 {
					log.Infof("~ nothing forwarded yet")
					continue
				}
				newest := st.Forwards[0]
				for _, f := range st.Forwards[1:] {
					if f.Since.After(newest.Since) {
						newest = f
					}
				}
				open(newest.Port)
			case '1', '2', '3', '4', '5', '6', '7', '8', '9':
				ports := statusPorts(sup.Status())
				if i := int(k - '1'); i < len(ports) {
					open(ports[i])
				} else {
					log.Infof("~ no row %c", k)
				}
			case '?', 'h':
				log.Infof(keyHelp)
			}
		}
	}()
}
