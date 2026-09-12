//go:build linux

package agent

import (
	"syscall"
)

// linuxProcAttr builds SysProcAttr with setpgid (own process group).
// Go's os/exec does NOT expose child rlimits via SysProcAttr on stock Go
// (only on the golang.org/x/sys fork used by some projects); instead the
// agent applies rlimits by re-execing itself through prlimit(1) when
// available, or falls back to pgroup-only. See confineApply in run.go.
func linuxProcAttr() any {
	return &syscall.SysProcAttr{Setpgid: true}
}

func killProcessGroup(pgid int) error {
	return syscall.Kill(-pgid, syscall.SIGKILL)
}
