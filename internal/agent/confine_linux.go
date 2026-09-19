//go:build linux

package agent

import (
	"syscall"
)

// linuxProcAttr builds SysProcAttr with setpgid (own process group).
//
// Process group only: Go's os/exec does not expose child rlimits through
// SysProcAttr, and nothing here re-execs through prlimit(1) to add them. The
// comment that used to say otherwise described a mechanism nobody wrote — see
// the package comment on confine.go.
func linuxProcAttr() any {
	return &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(pgid int) error {
	return syscall.Kill(-pgid, syscall.SIGKILL)
}
