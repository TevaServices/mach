package protocol

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// The wire format of these payloads is a compatibility surface: agents and
// control planes are updated independently, so the JSON field names are
// asserted literally rather than only round-tripped.

// Two transports, one protocol: a streamed session (many small frames, for the
// interactive console) and a one-shot exec (a single result object, the only
// shape that can be end-to-end sealed). These tests pin both.

func TestStreamOutWireFormat(t *testing.T) {
	payload := []byte{0xff, 0x00, 'a'}
	in := StreamOut{Stream: "stderr", B64: base64.StdEncoding.EncodeToString(payload)}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"stream", "b64"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("StreamOut JSON is missing %q: %s", k, raw)
		}
	}
	if len(fields) != 2 {
		t.Errorf("StreamOut JSON has unexpected fields: %s", raw)
	}

	var out StreamOut
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if out.Stream != in.Stream || out.B64 != in.B64 {
		t.Errorf("round trip = %+v, want %+v", out, in)
	}
	// Output is arbitrary bytes: base64 must survive non-UTF-8 intact.
	data, err := base64.StdEncoding.DecodeString(out.B64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(data) != string(payload) {
		t.Errorf("payload corrupted: %v", data)
	}
}

func TestStreamEndWireFormat(t *testing.T) {
	raw, err := json.Marshal(StreamEnd{ExitCode: 0})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := fields["exit_code"]; !ok {
		t.Errorf("StreamEnd JSON is missing exit_code: %s", raw)
	}
	// exit_code 0 is meaningful (success) and must not be dropped as empty.
	if string(fields["exit_code"]) != "0" {
		t.Errorf("exit_code = %s, want 0", fields["exit_code"])
	}
	// error is omitempty: a command that ran must not carry a failure reason.
	if _, ok := fields["error"]; ok {
		t.Errorf("empty error was serialized: %s", raw)
	}
	// Output never rides the terminal record; it arrives as StreamOut frames.
	// Re-adding these fields would silently double every stream's output.
	for _, gone := range []string{"stdout", "stderr", "b64"} {
		if _, ok := fields[gone]; ok {
			t.Errorf("StreamEnd JSON still carries %q: %s", gone, raw)
		}
	}

	var end StreamEnd
	if err := json.Unmarshal([]byte(`{"exit_code":126,"error":"blocked by command policy"}`), &end); err != nil {
		t.Fatalf("unmarshal refusal: %v", err)
	}
	if end.ExitCode != 126 || end.Error == "" {
		t.Errorf("refusal record = %+v, want the exit status and the reason", end)
	}
}

func TestStreamStartWireFormat(t *testing.T) {
	// A shell-mode start carries only the command; an argv-mode start only the
	// argv. An empty field must not be sent on the wire, so an agent can tell
	// "no argv" from "argv with one empty string" — the difference between
	// running nothing and running a command whose argument is empty.
	raw, err := json.Marshal(StreamStart{Command: "echo hi"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(fields["command"]) != `"echo hi"` {
		t.Errorf("command = %s", fields["command"])
	}
	if _, ok := fields["argv"]; ok {
		t.Errorf("empty argv was serialized: %s", raw)
	}

	raw, err = json.Marshal(StreamStart{Argv: []string{"printf", "%s\n", ""}})
	if err != nil {
		t.Fatalf("marshal argv: %v", err)
	}
	fields = nil
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal argv: %v", err)
	}
	if _, ok := fields["command"]; ok {
		t.Errorf("empty command was serialized: %s", raw)
	}
	var start StreamStart
	if err := json.Unmarshal(raw, &start); err != nil {
		t.Fatalf("round trip argv: %v", err)
	}
	if len(start.Argv) != 3 || start.Argv[2] != "" {
		t.Errorf("argv did not survive verbatim: %#v", start.Argv)
	}
}

func TestStreamStdinWireFormat(t *testing.T) {
	raw, err := json.Marshal(StreamStdin{B64: "aGk="})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if string(fields["b64"]) != `"aGk="` {
		t.Errorf("b64 = %s", fields["b64"])
	}
	// eof is a state, not a payload byte count: it must be absent when false so
	// a frame of zero bytes is not mistaken for end-of-input.
	if _, ok := fields["eof"]; ok {
		t.Errorf("false eof was serialized: %s", raw)
	}
}

func TestExecResultWireFormat(t *testing.T) {
	raw, err := json.Marshal(ExecResult{ExitCode: 3, Stdout: "out", Stderr: "err"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	// The one-shot path is buffered: its result object carries the output.
	for _, k := range []string{"exit_code", "stdout", "stderr"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("ExecResult JSON is missing %q: %s", k, raw)
		}
	}
	// error is omitempty: a successful command must not carry it.
	if _, ok := fields["error"]; ok {
		t.Errorf("empty error was serialized: %s", raw)
	}
}

func TestSealedExecWireFormats(t *testing.T) {
	// E2E: the control plane relays an opaque blob and the console's reply key,
	// and returns an opaque blob. Neither direction names the command or its
	// output — if either did, the seal would be pointless.
	raw, err := json.Marshal(SealedExecCommand{SealedB64: "c2VhbGVk", ReplyPub: "ab", Timeout: 30})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"sealed_b64", "reply_pub", "timeout"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("SealedExecCommand JSON is missing %q: %s", k, raw)
		}
	}
	if len(fields) != 3 {
		t.Errorf("SealedExecCommand JSON has unexpected fields: %s", raw)
	}

	raw, err = json.Marshal(SealedExecResult{SealedB64: "cmVwbHk="})
	if err != nil {
		t.Fatalf("marshal result: %v", err)
	}
	fields = nil
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal result: %v", err)
	}
	if len(fields) != 1 {
		t.Errorf("SealedExecResult JSON has unexpected fields: %s", raw)
	}
	if _, ok := fields["sealed_b64"]; !ok {
		t.Errorf("SealedExecResult JSON is missing sealed_b64: %s", raw)
	}
}

func TestPolicyWireFormats(t *testing.T) {
	// The mirror is the one frame whose payload decides what a machine will
	// refuse to run, so its field names are pinned literally: an agent and a
	// control plane updated independently must agree on them, and a typo here
	// would show up as a machine silently enforcing nothing.
	raw, err := json.Marshal(PolicyUpdate{Rules: "deny:rm -rf", Version: "abc123"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"rules", "version"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("PolicyUpdate JSON is missing %q: %s", k, raw)
		}
	}
	if len(fields) != 2 {
		t.Errorf("PolicyUpdate JSON has unexpected fields: %s", raw)
	}
	// An empty ruleset is an instruction, not an absent field: sending it must
	// be possible, or a withdrawn policy could not reach the machines.
	raw, err = json.Marshal(PolicyUpdate{})
	if err != nil {
		t.Fatalf("marshal empty: %v", err)
	}
	fields = nil
	_ = json.Unmarshal(raw, &fields)
	if _, ok := fields["rules"]; !ok {
		t.Errorf("an empty ruleset was dropped from the JSON: %s", raw)
	}
	if _, ok := fields["version"]; !ok {
		t.Errorf("an empty version was dropped from the JSON: %s", raw)
	}

	// The ack's version is a state a control plane compares, so it is never
	// omitempty; its error is a reason, so it is.
	raw, _ = json.Marshal(PolicyAck{Version: ""})
	fields = nil
	_ = json.Unmarshal(raw, &fields)
	if v, ok := fields["version"]; !ok || string(v) != `""` {
		t.Errorf("empty acks must still carry a version: %s", raw)
	}
	if _, ok := fields["error"]; ok {
		t.Errorf("a successful ack carried an error: %s", raw)
	}
}

// The delete notice is an envelope shape, not a payload, and it must stay one.
// The agent switches on the frame type alone, so a field added here would be
// silently ignored by every agent already deployed — and the failure would look
// like a machine that keeps reconnecting after it was deleted.
func TestDeletedFrameWireFormat(t *testing.T) {
	raw, err := json.Marshal(Envelope{Type: "deleted"})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if string(raw) != `{"type":"deleted"}` {
		t.Fatalf("deleted frame = %s, want exactly {\"type\":\"deleted\"} (no req_id, no payload)", raw)
	}
	// It must still read back as an envelope with the same tag.
	var env Envelope
	if err := json.Unmarshal(raw, &env); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if env.Type != "deleted" || env.ReqID != "" || len(env.Payload) != 0 {
		t.Fatalf("round trip changed the frame: %+v", env)
	}
}

// MachineInfo rides the fleet listing, which the console CLI and the web UI both
// read. "blocked" is additive, so an older client simply does not see it — but a
// blocked machine must still be *listed*, which is why this is a field on the
// machine rather than a reason to omit it from the response.
func TestMachineInfoBlockedField(t *testing.T) {
	raw, err := json.Marshal(MachineInfo{Name: "bcross-a", Online: true, Blocked: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := fields["blocked"]; !ok {
		t.Fatalf("blocked machine did not report the flag: %s", raw)
	}

	// An unblocked machine omits it, so the common case does not grow the
	// payload every client parses.
	raw, err = json.Marshal(MachineInfo{Name: "bcross-a", Online: true})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	fields = nil
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := fields["blocked"]; ok {
		t.Fatalf("unblocked machine reported a blocked field: %s", raw)
	}
}
