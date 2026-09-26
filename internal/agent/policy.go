package agent

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/TevaServices/mach/internal/policy"
	"github.com/TevaServices/mach/internal/protocol"
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
	// err is set when the guardrail could not be read at all. Evaluate refuses
	// everything while it is set: a machine whose own rules are missing is
	// exactly the case this layer exists to prevent, so the failure is
	// fail-closed as well as loud.
	err error
	p   policy.Policy
}

// globalPolicy is the machine's own guardrail: MACH_POLICY when set, otherwise
// policy.txt in the state dir. It is loaded once, at startup.
var globalPolicy lazyPolicy

// LoadLocalPolicy reads the machine's own guardrail. It is called at startup,
// *before* the privilege drop.
//
// That ordering is the fix for a real hole. The load used to be lazy, at the
// first command — which is after DropPrivileges() — so a root install that
// dropped to nobody and left a root-owned policy.txt got EACCES, and the error
// left an empty ruleset with no log line, for the life of the process. Every
// command, sealed or not, ran with the one layer SECURITY-NOTES says "survives
// a hostile control plane" silently absent. MACH_POLICY was never affected, and
// that is what let the two options look equivalent in the documentation.
//
// A file that does not exist is not an error: no local rules is the default. A
// file that exists and cannot be read is, for the reason the control plane
// refuses to boot on an unreadable MACH_EXEC_POLICY_FILE — an operator cannot
// tell "no rules" from "the rules I configured" if both are silent.
func LoadLocalPolicy() error { return globalPolicy.loadStartup() }

// loadStartup runs the load exactly once and reports what it cost. The method
// form exists so a test can exercise a load on its own instance rather than on
// the process-wide one, which is set-once by construction.
func (l *lazyPolicy) loadStartup() error {
	l.once.Do(l.load)
	return l.err
}

// load is the body both entry points run exactly once.
func (l *lazyPolicy) load() {
	if v := os.Getenv("MACH_POLICY"); v != "" {
		l.installReported(v, "MACH_POLICY")
		return
	}
	path := policyPath()
	raw, err := os.ReadFile(path)
	switch {
	case err == nil:
		l.installReported(string(raw), path)
	case errors.Is(err, fs.ErrNotExist):
		// No local guardrail configured. The fleet-wide rules, if any, still
		// apply on this machine — those arrive over the connection.
		log.Printf("agent: local exec policy: none configured (%s absent, MACH_POLICY unset)", path)
	default:
		l.err = fmt.Errorf("cannot read %s: %w", path, err)
		log.Printf("agent: local exec policy: %v — refusing every command rather than running unguarded", l.err)
	}
}

// installReported installs spec and reports any line the grammar ignored, then
// logs what is in force. The ruleset is printed either way: "what is this
// machine enforcing" should be answerable from the journal rather than assumed.
func (l *lazyPolicy) installReported(spec, source string) {
	ignored := l.p.Replace(spec)
	if rules := l.p.Describe(); len(rules) > 0 {
		log.Printf("agent: local exec policy from %s: %s", source, strings.Join(rules, " "))
	} else {
		log.Printf("agent: local exec policy from %s: none", source)
	}
	if w := policy.IgnoredWarning(ignored); w != "" {
		log.Printf("agent: local exec policy from %s: %s", source, w)
	}
}

func (l *lazyPolicy) Evaluate(command string, argv []string) string {
	// A caller that never called LoadLocalPolicy (a test, or code that ignored
	// its error) still gets the rules loaded — and still gets the failure, which
	// is turned into a refusal rather than into silence.
	l.once.Do(l.load)
	if l.err != nil {
		return "denied by command policy (this machine's own policy could not be read: " + l.err.Error() + ")"
	}
	return l.p.Evaluate(command, argv)
}

// install replaces the process-wide guardrail at runtime. The lazy load is
// marked done so a later Evaluate never re-reads the environment out from under
// whoever installed the rules.
func (l *lazyPolicy) install(spec string) {
	l.once.Do(func() {})
	l.err = nil
	l.installReported(spec, "installed")
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
// checkCommand judges a command against the agent's own guardrail and the
// mirrored fleet rules. cmd.FleetApproved is honored only for the fleet layer:
// the control plane dispatches an approved exception with it set, and the
// mirrored copy of the same ruleset stands down for this one command — never
// for the machine's own policy, which no upstream can override. A forged flag
// from the machine's own shell cannot appear here: the field arrives on the
// wire from the control plane, on a connection the agent pinned at enrollment,
// and the agent's own dispatch of a plain command never sets it.
func checkCommand(cmd protocol.ExecCommand) string {
	if cmd.FleetApproved {
		// Only the machine's own rules still judge it. The mirrored set is the
		// one the approval exempted this command from.
		if reason := globalPolicy.Evaluate(cmd.Command, cmd.Argv); reason != "" {
			return reason
		}
		return ""
	}
	if reason := globalPolicy.Evaluate(cmd.Command, cmd.Argv); reason != "" {
		return reason
	}
	if reason := fleetRules.Evaluate(cmd.Command, cmd.Argv); reason != "" {
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
