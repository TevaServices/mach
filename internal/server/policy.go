package server

import (
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bcross/mach/internal/policy"
)

// Global exec policy — the fleet-wide half of mach's command control.
//
// The other half is the per-machine guardrail the agent evaluates locally
// (MACH_POLICY / policy.txt, see internal/agent/policy.go). Both read the
// same grammar from internal/policy, so a rule means the same thing wherever
// it is written. What differs is who can change it and where it is enforced:
//
//   - the agent's policy lives on the machine and is evaluated by the agent
//     process, so nothing upstream — not even a compromised control plane —
//     can talk the agent out of it;
//   - this one lives in the control plane and is evaluated here, in
//     handleExec, before a command is dispatched to any agent.
//
// This is the answer to "block this command across the whole fleet": one file
// on the control plane, and every API key, every scope, and every machine is
// subject to it. It is enforced unconditionally — no scope or exec allowlist
// exempts a caller.
//
// It is a block list for mistakes and policy violations, NOT a confinement
// boundary: it matches text, and text can be obfuscated. See the package
// comment on internal/policy for the honest limits of what it can promise.
type execPolicy struct {
	mu   sync.RWMutex
	p    policy.Policy
	src  string // "MACH_EXEC_POLICY", a file path, or "" when unset
	path string // non-empty when the rules come from a re-readable file
	mod  time.Time
}

// execRefused is recorded as the exit status of a command the global policy
// blocked — the shell's "found but not executable", which is what a caller
// would have seen had the block been a missing binary rather than a rule.
const execRefused = 126

const (
	execPolicyEnv     = "MACH_EXEC_POLICY"
	execPolicyFileEnv = "MACH_EXEC_POLICY_FILE"

	// How often a policy file's mtime is re-checked. Editing the file is the
	// intended way to change the block list, so it should not require a
	// restart; 15s is well below the time it takes to notice in practice and
	// costs one stat per tick.
	execPolicyPollInterval = 15 * time.Second
)

// Replace installs rules wholesale (the parser resets first, so this never
// accumulates). An empty spec clears the policy.
func (e *execPolicy) Replace(spec, source string) {
	e.mu.Lock()
	e.p.Replace(spec)
	e.src = source
	e.mu.Unlock()
}

// Evaluate returns "" when the command is permitted, or a human-readable
// reason when it is refused.
func (e *execPolicy) Evaluate(command string, argv []string) string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.p.Evaluate(command, argv)
}

func (e *execPolicy) Rules() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.p.Describe()
}

func (e *execPolicy) Source() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.src
}

// loadEnv installs the policy configured through the environment.
//
// A configured-but-unreadable file is fatal: a control plane that boots with
// its block list silently missing is worse than one that refuses to start, and
// a half-mounted secrets volume is exactly how that happens by accident. An
// empty file, by contrast, is a legitimate empty policy.
func (e *execPolicy) loadEnv() error {
	if path := strings.TrimSpace(os.Getenv(execPolicyFileEnv)); path != "" {
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fi, _ := os.Stat(path)
		var mod time.Time
		if fi != nil {
			mod = fi.ModTime()
		}
		e.mu.Lock()
		e.p.Replace(string(raw))
		e.src, e.path, e.mod = path, path, mod
		e.mu.Unlock()
		return nil
	}
	if spec := os.Getenv(execPolicyEnv); spec != "" {
		e.Replace(spec, execPolicyEnv)
	}
	return nil
}

// reloadFile re-reads the policy file if it changed on disk. Returns true when
// the rules were replaced, so the caller can log the new state.
func (e *execPolicy) reloadFile() bool {
	e.mu.RLock()
	path, mod := e.path, e.mod
	e.mu.RUnlock()
	if path == "" {
		return false
	}
	fi, err := os.Stat(path)
	if err != nil || !fi.ModTime().After(mod) {
		return false
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		// Keep serving the last good rules rather than failing open.
		return false
	}
	e.mu.Lock()
	e.p.Replace(string(raw))
	e.mod = fi.ModTime()
	e.mu.Unlock()
	return true
}

// execPolicyCheck returns a refusal reason, or "" to allow. Called on every
// exec, before anything is dispatched.
func (s *Server) execPolicyCheck(command string, argv []string) string {
	return s.execPolicy.Evaluate(command, argv)
}

// commandForDisplay renders a request's command for audit rows and policy
// checks: argv-mode requests have no Command string, and both the audit trail
// and the block list need to see what was actually asked for.
func commandForDisplay(command string, argv []string) string {
	if command != "" || len(argv) == 0 {
		return command
	}
	return strings.Join(argv, " ")
}
