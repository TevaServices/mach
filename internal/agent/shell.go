package agent

import (
	"fmt"
	"os/exec"
	"runtime"
	"sync"
)

// Shell selection. Preference order is explicit and per-OS; the first
// shell found on PATH wins. Bash is the preferred default everywhere it
// exists — it is the most predictable scripting shell and the one the
// troubleshooting agent reasons best in. Windows hosts get PowerShell
// (cmd as last resort).
//
//	linux:   bash → sh
//	darwin:  bash → zsh → sh   (macOS ships bash 3.2; zsh is the user default)
//	windows: PowerShell → pwsh → cmd
type shellKind int

const (
	shellPosix      shellKind = iota // sh/bash/zsh:  shell -c CMD
	shellPowerShell                  // powershell -NoProfile -NonInteractive -Command CMD
	shellCmd                         // cmd /c CMD
)

type resolvedShell struct {
	path string
	kind shellKind
}

var (
	shellOnce   sync.Once
	shellCached resolvedShell
	shellErr    error
)

func shellCandidates() []struct {
	path string
	kind shellKind
} {
	switch runtime.GOOS {
	case "darwin":
		return []struct {
			path string
			kind shellKind
		}{
			{"bash", shellPosix},
			{"zsh", shellPosix},
			{"sh", shellPosix},
		}
	case "windows":
		return []struct {
			path string
			kind shellKind
		}{
			{"powershell", shellPowerShell},
			{"pwsh", shellPowerShell},
			{"cmd", shellCmd},
		}
	default: // linux and other unix
		return []struct {
			path string
			kind shellKind
		}{
			{"bash", shellPosix},
			{"sh", shellPosix},
		}
	}
}

// resolveShell picks the best available shell for this OS, with fallbacks.
func resolveShell() (resolvedShell, error) {
	shellOnce.Do(func() {
		for _, c := range shellCandidates() {
			if p, err := exec.LookPath(c.path); err == nil {
				shellCached = resolvedShell{path: p, kind: c.kind}
				return
			}
		}
		if runtime.GOOS != "windows" {
			// Absolute fallback: POSIX sh is contractual on unix.
			shellCached = resolvedShell{path: "/bin/sh", kind: shellPosix}
			return
		}
		shellErr = fmt.Errorf("no shell found (tried powershell, pwsh, cmd)")
	})
	return shellCached, shellErr
}

// shellArgs builds the exec argv for running a command string in the shell.
func (s resolvedShell) args(command string) []string {
	switch s.kind {
	case shellPowerShell:
		return []string{"-NoProfile", "-NonInteractive", "-Command", command}
	case shellCmd:
		return []string{"/c", command}
	default:
		return []string{"-c", command}
	}
}