package forward

import (
	"errors"

	"golang.org/x/sys/windows"
)

// busyReason explains a listen error that means the port is not ours to
// use, or returns "" for any other failure. WSAEACCES is what Windows
// returns for ports inside an excluded range (Hyper-V, WSL and Docker
// reserve blocks of them).
func busyReason(err error) string {
	switch {
	case errors.Is(err, windows.WSAEADDRINUSE):
		return "address already in use"
	case errors.Is(err, windows.WSAEACCES):
		return "reserved by Windows (excluded port range; see `netsh int ipv4 show excludedportrange protocol=tcp`)"
	}
	return ""
}
