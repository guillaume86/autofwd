//go:build !windows

package ui

import "os"

// enableVT is a no-op outside Windows: every terminal that passes
// IsTerminal understands the handful of sequences used here.
func enableVT(*os.File) bool { return true }
