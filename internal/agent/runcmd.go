package agent

import "os/exec"

// runCmd executes a helper command, capturing combined output.
func runCmd(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).CombinedOutput()
	return string(out), err
}
