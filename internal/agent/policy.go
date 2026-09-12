package agent

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/bcross/mach/internal/policy"
	"github.com/bcross/mach/internal/protocol"
)

// maxFleetPolicyBytes bounds a ruleset pushed from the control plane.
const maxFleetPolicyBytes = 64 << 10

// Per-machine command guardrail, configured via MACH_POLICY env (survives in
// the service unit) or policy.txt in the state dir. The grammar and matching
// semantics live in internal/policy, which the control plane's global policy
// shares:
//
//	deny:rm -rf          refuse commands containing this substring
//	allowonly            deny by default; every command must start with an
//	                     allow: rule
//	allow:systemctl      permit commands starting with this prefix
//
// This is a guardrail, not a confinement boundary — see the package comment
// on internal/policy for what it can and cannot promise.
type lazyPolicy struct {
	once sync.Once
	p    policy.Policy
}

// globalPolicy is loaded on first use: reading the state dir at process
// start would run before the agent has dropped privileges.
var globalPolicy lazyPolicy

func (l *lazyPolicy) Evaluate(command string, argv []string) string {
	l.once.Do(func() {
		if v := os.Getenv("MACH_POLICY"); v != "" {
			l.p.Replace(v)
			return
		}
		if raw, err := os.ReadFile(policyPath()); err == nil {
			l.p.Replace(string(raw))
		}
	})
	return l.p.Evaluate(command, argv)
}

// install replaces the process-wide guardrail at runtime. The lazy load is
// marked done so a later Evaluate never re-reads the environment out from under
// whoever installed the rules.
func (l *lazyPolicy) install(spec string) {
	l.once.Do(func() {})
	l.p.Replace(spec)
}

func policyPath() string {
	return StateDir() + "/policy.txt"
}

// fleetPolicy mirrors the control plane's fleet-wide rules.
//
// The control plane cannot read a sealed command, so it cannot apply its own
// block list to one — the text of the command does not exist on the control
// plane at all. It exists here, after decryption. So the rules travel to the
// machine (protocol.PolicyUpdate, pushed at connect and on every change) and
// are evaluated here, at the same point as the local guardrail.
//
// This is not a way to weaken the machine's own rules: both layers are
// evaluated and a refusal from either stands. The rules this carries are the
// fleet operator's; the local ones are the machine owner's, and nothing
// upstream can loosen them. Neither is a sandbox — see internal/policy.
type fleetPolicy struct {
	mu      sync.RWMutex
	p       policy.Policy
	version string
}

// fleetRules is the control plane's mirrored ruleset for this process.
var fleetRules fleetPolicy

// install replaces the mirrored ruleset and returns the version now held. An
// empty spec clears it, which is how an operator who withdraws a fleet policy
// stops machines enforcing it.
func (f *fleetPolicy) install(spec, version string) {
	f.mu.Lock()
	f.p.Replace(spec)
	f.version = version
	f.mu.Unlock()
}

// Evaluate returns a refusal reason, or "" to allow.
func (f *fleetPolicy) Evaluate(command string, argv []string) string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.p.Evaluate(command, argv)
}

// Version reports the ruleset version being enforced ("" when none).
func (f *fleetPolicy) Version() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.version
}

// checkCommand is the single guardrail evaluation every exec path goes through
// — one-shot and streamed, sealed and plaintext. Two rule sets, both enforced,
// in a fixed order so the machine's own rules always get the first word.
func checkCommand(command string, argv []string) string {
	if reason := globalPolicy.Evaluate(command, argv); reason != "" {
		return reason
	}
	if reason := fleetRules.Evaluate(command, argv); reason != "" {
		// Name the layer: the operator who wrote the fleet rule and the one who
		// wrote the local rule may be different people, and a refusal that does
		// not say which rule refused it sends them to the wrong place.
		return "blocked by the fleet-wide exec policy (enforced on this machine, " +
			"where a sealed command is readable): " + reason
	}
	return ""
}

// handlePolicyFrame installs the fleet-wide ruleset the control plane pushed
// and acknowledges the version, so the control plane can tell "the machine has
// my rules" from "the machine never got them" — silence would otherwise read as
// success on a control that is enforced nowhere the operator can see.
//
// The ruleset is bounded before it is parsed: this arrives over a connection
// the control plane holds, but an agent that accepts an unbounded rule spec has
// handed a remote peer a memory-growth primitive for no reason.
func handlePolicyFrame(conn *protocol.WSConn, env protocol.Envelope) error {
	var upd protocol.PolicyUpdate
	if err := json.Unmarshal(env.Payload, &upd); err != nil {
		ackPolicy(conn, "", "malformed policy frame")
		return err
	}
	if len(upd.Rules) > maxFleetPolicyBytes {
		ackPolicy(conn, "", "policy ruleset too large")
		return fmt.Errorf("policy ruleset is %d bytes (limit %d)", len(upd.Rules), maxFleetPolicyBytes)
	}
	// The version is the control plane's fingerprint of what it sent; the
	// agent recomputes it rather than trusting the field, so a mismatch means
	// the two ends disagree about what was installed rather than that one of
	// them said so.
	want := policy.Fingerprint(upd.Rules)
	if upd.Version != "" && upd.Version != want {
		ackPolicy(conn, "", "policy version does not match its rules")
		return fmt.Errorf("policy version %q does not match the rules it arrived with", upd.Version)
	}
	fleetRules.install(upd.Rules, want)
	rules := fleetRules.Rules()
	if len(rules) == 0 {
		log.Printf("agent: fleet exec policy cleared")
	} else {
		log.Printf("agent: fleet exec policy installed (%s): %s", want, strings.Join(rules, " "))
	}
	ackPolicy(conn, want, "")
	return nil
}

// ackPolicy reports the ruleset version now in force (or why none is).
func ackPolicy(conn *protocol.WSConn, version, errMsg string) {
	payload, err := json.Marshal(protocol.PolicyAck{Version: version, Error: errMsg})
	if err != nil {
		return
	}
	if err := conn.WriteEnvelope(protocol.Envelope{Type: "policy_ack", ReqID: version, Payload: payload}); err != nil {
		log.Printf("agent: could not acknowledge the fleet policy: %v", err)
	}
}

// Rules describes the ruleset in force, for logs and tests.
func (f *fleetPolicy) Rules() []string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.p.Describe()
}
