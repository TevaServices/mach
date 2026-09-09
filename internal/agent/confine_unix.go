//go:build linux || darwin

package agent

import (
	"os/exec"
	"syscall"
)

// confineProcAttr gives the child its own process group.
func confineProcAttr() *syscall.SysProcAttr {
	return &syscall.SysProcAttr{Setpgid: true}
}

// applyConfinement sets confinement fields on the command pre-start.
func applyConfinement(c *exec.Cmd) {
	if c.SysProcAttr == nil {
		c.SysProcAttr = confineProcAttr()
	}
}

// killProcessTree kills the child's whole process group (negative pgid).
func killProcessTree(c *exec.Cmd) {
	if c.Process == nil {
		return
	}
	pgid := c.Process.Pid
	_ = syscall.Kill(-pgid, syscall.SIGKILL)
}