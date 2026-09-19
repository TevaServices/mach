// Package agent: OS-level execution confinement for remote commands.
//
// The substring policy layer is a
// foot-guard. This adds real OS enforcement where the platform allows:
//
//   - linux: each command runs in its own process group (setpgid) and is
//     killed with SIGKILL to -pgid on timeout — grandchildren die too.
//   - darwin: own process group; tree kill via negative pgid.
//   - windows: timeout + output caps only (no Job object via os/exec).
//
// There are NO resource limits (CPU, file size) on a command: Go's os/exec
// cannot set child rlimits through SysProcAttr, and nothing here re-execs
// through prlimit(1). The comments and constants that claimed otherwise were
// describing a mechanism that was never written, which is worse than the
// absence — an operator reading confinementNote in a log would have believed
// a command could not spin a CPU for a week.
//
// This is defense-in-depth (timeout + output cap + pgroup kill), not a
// full sandbox — no seccomp/Seatbelt profiles yet.
package agent

import "time"

// confinement tuning (documented; not yet env-tunable).
const (
	// confineGracePeriod is how long a killed command's process group is given
	// before the agent gives up waiting on it. There are deliberately no CPU or
	// file-size constants here: see the package comment for why there are no
	// resource limits at all.
	confineGracePeriod = 5 * time.Second
)

// confinementNote describes the active confinement for logs/audit.
func confinementNote() string {
	switch runtimeGOOSConfine() {
	case "linux":
		return "pgroup-kill"
	case "darwin":
		return "pgroup-kill"
	default:
		return "timeout+output-caps only"
	}
}
