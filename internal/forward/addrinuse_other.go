//go:build !windows

package forward

import (
	"errors"
	"syscall"
)

// busyReason explains a listen error that means the port is not ours to
// use, or returns "" for any other failure.
func busyReason(err error) string {
	if errors.Is(err, syscall.EADDRINUSE) {
		return "address already in use"
	}
	return ""
}
