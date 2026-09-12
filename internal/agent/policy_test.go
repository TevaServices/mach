package agent

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bcross/mach/internal/e2e"
	"github.com/bcross/mach/internal/policy"
	"github.com/bcross/mach/internal/protocol"
)

// sealedExecForTest runs one sealed command through the agent's sealed exec path
// and returns the result the console would see — which means opening the reply
// with the console's ephemeral key, exactly as the console does.
func sealedExecForTest(t *testing.T, command string) protocol.ExecResult {
	t.Helper()
	stateDir := t.TempDir()
	conn, peer := streamPipe(t)

	// The machine's E2E key, as registered at enrollment.
	machine, err := LoadOrCreateE2EKey(stateDir)
	if err != nil {
		t.Fatalf("machine key: %v", err)
	}
	console, err := e2e.GenerateKeyPair()
	if err != nil {
		t.Fatalf("console key: %v", err)
	}

	inner, _ := json.Marshal(protocol.ExecCommand{Command: command})
	sealed, err := e2e.Seal(machine.Public[:], inner)
	if err != nil {
		t.Fatalf("seal: %v", err)
	}
	req := protocol.SealedExecCommand{
		SealedB64: base64.StdEncoding.EncodeToString(sealed),
		ReplyPub:  console.PublicKeyHex(),
		Timeout:   5,
	}
	payload, _ := json.Marshal(req)
	// The handler takes the keypair, not a directory: that is what lets a
	// temporary session, whose key exists only in memory, run a sealed command
	// without writing one. This test still loads it from a state dir, so the
	// file-backed path stays exercised.
	handleSealedExec(conn, protocol.Envelope{Type: "exec", ReqID: "sealed-1", Payload: payload},
		req, machine, make(chan struct{}, 1))

	env := readEnvelope(t, peer)
	if env.Type != "exec_result" {
		t.Fatalf("frame = %q, want exec_result", env.Type)
	}
	var wire protocol.SealedExecResult
	if err := json.Unmarshal(env.Payload, &wire); err != nil {
		t.Fatalf("sealed result payload: %v", err)
	}
	raw, err := base64.StdEncoding.DecodeString(wire.SealedB64)
	if err != nil {
		t.Fatalf("sealed result is not base64: %v", err)
	}
	// If this fails the reply was not sealed to the console, which would mean
	// the result — and any refusal reason in it — was readable in transit.
	opened, err := e2e.Open(&console.Private, raw)
	if err != nil {
		t.Fatalf("console could not open the sealed result: %v", err)
	}
	var res protocol.ExecResult
	if err := json.Unmarshal(opened, &res); err != nil {
		t.Fatalf("sealed result is not an ExecResult: %v", err)
	}
	return res
}

// The property this whole mirroring path exists for: a SEALED command is still
// subject to the fleet-wide block list. The control plane cannot apply its own
// rules to ciphertext, so they run here, where the command is readable — and the
// refusal comes back through the seal like any other result.
func TestFleetRulesBindSealedCommands(t *testing.T) {
	globalPolicy.install("")
	fleetRules.install("deny:sealed-fleet-marker\n", policy.Fingerprint("deny:sealed-fleet-marker\n"))
	t.Cleanup(func() { fleetRules.install("", "") })

	res := sealedExecForTest(t, "echo sealed-fleet-marker")
	if res.ExitCode != 126 {
		t.Fatalf("exit code = %d (%q), want 126: a sealed command ran despite the fleet policy", res.ExitCode, res.Error)
	}
	if !strings.Contains(res.Error, "sealed-fleet-marker") {
		t.Errorf("refusal = %q, want it to name the rule that refused it", res.Error)
	}
	// It says which layer refused: the fleet rules and the machine's own rules
	// are written by different people, and a refusal that names the wrong one
	// sends the operator to the wrong place.
	if !strings.Contains(res.Error, "fleet-wide exec policy") {
		t.Errorf("refusal = %q, want it to name the fleet layer", res.Error)
	}

	// A command the rules do not match still runs: the mirror is a block list,
	// not a lockdown.
	res = sealedExecForTest(t, "echo unrelated")
	if res.ExitCode != 0 {
		t.Errorf("unrelated sealed command: exit %d (%q), want 0", res.ExitCode, res.Error)
	}
}

// What the control plane sends cannot loosen what the machine owner wrote. Both
// layers are evaluated; an empty fleet ruleset is not a way past the local one.
func TestFleetRulesCannotWeakenLocalRules(t *testing.T) {
	globalPolicy.install("deny:local-marker\n")
	fleetRules.install("", "")
	t.Cleanup(func() {
		globalPolicy.install("")
		fleetRules.install("", "")
	})

	if reason := checkCommand("echo local-marker", nil); reason == "" {
		t.Fatal("an empty fleet ruleset displaced the machine's own rules")
	}
	// And a fleet ruleset that allows everything leaves the local deny in force.
	fleetRules.install("allowonly\nallow:echo\n", policy.Fingerprint("allowonly\nallow:echo\n"))
	fleetRules.install("", "")
	if reason := checkCommand("echo local-marker", nil); reason == "" {
		t.Error("the local rule stopped applying")
	}
}

// Clearing the fleet rules stops them being enforced. An operator who withdraws
// a fleet policy must not leave every machine enforcing the withdrawn version.
func TestClearedFleetRulesAreNotEnforced(t *testing.T) {
	globalPolicy.install("")
	fleetRules.install("deny:fleet-marker\n", policy.Fingerprint("deny:fleet-marker\n"))
	if reason := checkCommand("echo fleet-marker", nil); reason == "" {
		t.Fatal("fleet rules were not applied")
	}
	fleetRules.install("", policy.Fingerprint(""))
	if reason := checkCommand("echo fleet-marker", nil); reason != "" {
		t.Errorf("withdrawn fleet rule still refuses: %q", reason)
	}
	t.Cleanup(func() { fleetRules.install("", "") })
}

// The mirror is only trusted when it is self-consistent: a frame whose version
// does not describe its own rules is refused rather than installed, so the
// control plane cannot be told a version the machine is not enforcing.
func TestPolicyFrameRejectsAMismatchedVersion(t *testing.T) {
	globalPolicy.install("")
	fleetRules.install("", "")
	conn, peer := streamPipe(t)

	payload, _ := json.Marshal(protocol.PolicyUpdate{Rules: "deny:x\n", Version: "not-the-fingerprint"})
	if err := handlePolicyFrame(conn, protocol.Envelope{Type: "policy", Payload: payload}); err == nil {
		t.Fatal("a frame whose version does not match its rules was accepted")
	}
	env := readEnvelope(t, peer)
	if env.Type != "policy_ack" {
		t.Fatalf("frame = %q, want a policy_ack", env.Type)
	}
	var ack protocol.PolicyAck
	_ = json.Unmarshal(env.Payload, &ack)
	if ack.Error == "" || ack.Version != "" {
		t.Errorf("ack = %+v, want it to report the failure and claim no version", ack)
	}
	// Nothing was installed.
	if reason := checkCommand("echo x", nil); reason != "" {
		t.Errorf("a rejected frame changed the rules in force: %q", reason)
	}

	// The honest case installs and acknowledges the recomputed fingerprint.
	good, _ := json.Marshal(protocol.PolicyUpdate{Rules: "deny:x\n", Version: policy.Fingerprint("deny:x\n")})
	if err := handlePolicyFrame(conn, protocol.Envelope{Type: "policy", Payload: good}); err != nil {
		t.Fatalf("valid frame refused: %v", err)
	}
	env = readEnvelope(t, peer)
	// A fresh value, not the one above: "error" is omitempty, so unmarshalling
	// into a struct that already holds an error would keep it.
	var okAck protocol.PolicyAck
	_ = json.Unmarshal(env.Payload, &okAck)
	if okAck.Version != policy.Fingerprint("deny:x\n") || okAck.Error != "" {
		t.Errorf("ack = %+v, want the version now in force", okAck)
	}
	if reason := checkCommand("echo x", nil); reason == "" {
		t.Error("the installed ruleset is not being enforced")
	}
	t.Cleanup(func() { fleetRules.install("", "") })
}

// An unbounded ruleset is refused: this arrives over a connection the control
// plane holds, but an agent that parses whatever it is handed has given a remote
// peer a memory-growth primitive for nothing.
func TestPolicyFrameRejectsAnOversizeRuleset(t *testing.T) {
	globalPolicy.install("")
	fleetRules.install("", "")
	conn, peer := streamPipe(t)

	big := strings.Repeat("deny:aaaa\n", maxFleetPolicyBytes/5)
	payload, _ := json.Marshal(protocol.PolicyUpdate{Rules: big, Version: policy.Fingerprint(big)})
	if err := handlePolicyFrame(conn, protocol.Envelope{Type: "policy", Payload: payload}); err == nil {
		t.Fatal("an oversize ruleset was accepted")
	}
	env := readEnvelope(t, peer)
	var ack protocol.PolicyAck
	_ = json.Unmarshal(env.Payload, &ack)
	if !strings.Contains(ack.Error, "too large") {
		t.Errorf("ack = %+v, want it to refuse the size", ack)
	}
	if reason := checkCommand("echo aaaa", nil); reason != "" {
		t.Errorf("an oversize frame changed the rules in force: %q", reason)
	}
}

// Output that may have been cut short is reported as such. The console stops
// reading at the terminal record, so bytes still in flight when it is written are
// bytes nobody ever sees — and a truncated stream that looks complete is worse
// than one that says it was cut.
func TestIncompleteOutputIsReported(t *testing.T) {
	if got := withDrainNote("", false); got != "" {
		t.Errorf("a clean drain carried a note: %q", got)
	}
	got := withDrainNote("", true)
	if !strings.Contains(got, "incomplete") {
		t.Errorf("note = %q, want it to say the output may be incomplete", got)
	}
	// A command that also failed says both things: the exit status is not
	// replaced by the drain note.
	got = withDrainNote("timed out", true)
	if !strings.Contains(got, "timed out") || !strings.Contains(got, "incomplete") {
		t.Errorf("note = %q, want the failure and the truncation", got)
	}
}
