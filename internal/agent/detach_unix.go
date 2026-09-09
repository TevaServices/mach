//go:build linux || darwin

package agent

import "syscall"

// detachSysProcAttr puts the replacement agent process in its own session
// so it survives the death of the updating process.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setsid: true}
}
