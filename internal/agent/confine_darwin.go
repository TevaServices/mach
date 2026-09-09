//go:build darwin

package agent

import "syscall"

// darwinProcAttr: own process group so the process tree is killable.
// Child rlimits are not supported via os/exec on darwin; output caps and
// the command timeout provide the bounds instead.
func darwinProcAttr() any {
	return &syscall.SysProcAttr{Setpgid: true}
}