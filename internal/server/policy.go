package server

import (
	"encoding/json"
	"log"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/policy"
	"github.com/bcross/mach/internal/protocol"
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

// pollPolicyOnce re-reads the policy file when it changed and mirrors the result
// onto every connected agent. The ticker calls this; tests call it directly, so
// the reload-and-propagate path is covered without waiting out an interval and
// without a mutable interval read from live goroutines.
func (s *Server) pollPolicyOnce() {
	if !s.execPolicy.reloadFile() {
		return
	}
	log.Printf("server: %s changed on disk; reloaded", s.execPolicy.Source())
	s.logExecPolicy()
	// The rules are enforced on the machines (that is the only place a sealed
	// command is readable), so an edit here has to reach every connected agent.
	// Without this the control plane would hold the new rules while every
	// running machine kept enforcing the old ones until it happened to reconnect.
	s.broadcastFleetPolicy()
}

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

// Spec renders the rules the way the grammar writes them, which is what an
// agent parses when the ruleset is mirrored onto the machine. Empty when there
// are no rules — and an empty spec is a meaningful thing to send: it clears
// whatever a machine was enforcing before.
func (e *execPolicy) Spec() string {
	return strings.Join(e.Rules(), "\n")
}

// Version fingerprints the ruleset so both ends can tell whether they hold the
// same one.
func (e *execPolicy) Version() string {
	return policy.Fingerprint(e.Spec())
}

// pushFleetPolicy mirrors the current ruleset onto one agent connection.
//
// Always sent, at every connect, including when it is empty: a machine that
// reconnects after the operator withdrew a fleet policy has to be told to stop
// enforcing the old one, and "no message" cannot say that.
func (s *Server) pushFleetPolicy(ac *broker.AgentConn) {
	spec, version := s.execPolicy.Spec(), s.execPolicy.Version()
	payload, err := json.Marshal(protocol.PolicyUpdate{Rules: spec, Version: version})
	if err != nil {
		s.logf("could not encode the fleet policy for %q: %v", ac.Name, err)
		return
	}
	if err := ac.Conn.WriteEnvelope(protocol.Envelope{Type: "policy", Payload: payload}); err != nil {
		s.logf("could not push the fleet policy to %q: %v", ac.Name, err)
	}
}

// broadcastFleetPolicy mirrors a changed ruleset onto every connected agent.
// The rules are enforced on the machines (that is where a sealed command is
// readable), so a change that only updated this process would leave every
// running agent enforcing the previous version until it happened to reconnect.
func (s *Server) broadcastFleetPolicy() {
	s.broadcastPolicy(s.execPolicy.Version())
}

// broadcastPolicy pushes the current ruleset to every live agent and logs the
// version they were sent.
func (s *Server) broadcastPolicy(version string) {
	n := 0
	s.br.Each(func(ac *broker.AgentConn) {
		s.pushFleetPolicy(ac)
		n++
	})
	if n > 0 {
		s.logf("fleet exec policy %s pushed to %d agent(s)", version, n)
	}
}

// recordPolicyAck notes which ruleset version a machine is enforcing, and warns
// when it is not the current one — an agent enforcing yesterday's rules is a
// silent hole in a control the operator believes is fleet-wide.
func (s *Server) recordPolicyAck(machine string, env protocol.Envelope) {
	var ack protocol.PolicyAck
	if err := json.Unmarshal(env.Payload, &ack); err != nil {
		s.logf("agent %q sent an unreadable policy_ack", machine)
		return
	}
	if ack.Error != "" {
		s.logf("agent %q could not install the fleet policy: %s", machine, ack.Error)
		return
	}
	s.policyMu.Lock()
	if s.policyAcks == nil {
		s.policyAcks = map[string]string{}
	}
	s.policyAcks[machine] = ack.Version
	s.policyMu.Unlock()

	if want := s.execPolicy.Version(); ack.Version != want {
		s.logf("agent %q is enforcing fleet policy %s, not the current %s — it will be updated on its next connect",
			machine, ack.Version, want)
	}
}

// policyAck reports the version a machine last confirmed ("" when unknown).
func (s *Server) policyAck(machine string) string {
	s.policyMu.Lock()
	defer s.policyMu.Unlock()
	return s.policyAcks[machine]
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
