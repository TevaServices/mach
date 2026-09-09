//go:build windows

package agent

import "syscall"

// detachSysProcAttr on Windows: create in its own process group.
func detachSysProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{CreationFlags: syscall.CREATE_NEW_PROCESS_GROUP}
}
