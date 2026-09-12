// Package agent: OS-level execution confinement for remote commands.
//
// The substring policy layer is a
// foot-guard. This adds real OS enforcement where the platform allows:
//
//   - linux: each command runs in its own process group (setpgid) and is
//     killed with SIGKILL to -pgid on timeout — grandchildren die too.
//     Resource limits via prlimit(1) are applied when present.
//   - darwin: own process group; tree kill via negative pgid.
//   - windows: timeout + output caps only (no Job object via os/exec).
//
// This is defense-in-depth (timeout + output cap + pgroup kill), not a
// full sandbox — no seccomp/Seatbelt profiles yet.
package agent

import "time"

// confinement tuning (documented; not yet env-tunable).
const (
	confineCPUSeconds  = 600  // prlimit CPU cap per command (linux)
	confineFileMaxMiB  = 1024 // prlimit FSIZE cap (linux)
	confineGracePeriod = 5 * time.Second
)

// confinementNote describes the active confinement for logs/audit.
func confinementNote() string {
	switch runtimeGOOSConfine() {
	case "linux":
		return "pgroup-kill+prlimit(cpu,fsize)"
	case "darwin":
		return "pgroup-kill"
	default:
		return "timeout+output-caps only"
	}
}
