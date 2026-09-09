package console

import "os/exec"

func execLocalCmd(cmdline string) *exec.Cmd { return exec.Command("sh", "-c", cmdline) }