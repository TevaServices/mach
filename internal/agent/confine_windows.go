//go:build windows

package agent

import (
	"os/exec"
)

// applyConfinement is best-effort on windows: os/exec exposes no Job
// objects; bounding comes from the timeout + output caps.
func applyConfinement(c *exec.Cmd) {}

// killProcessTree is not supported via stdlib on windows; the direct
// child is killed by CommandContext's process handle.
func killProcessTree(c *exec.Cmd) {}

func runtimeGOOSConfine() string { return "windows" }
