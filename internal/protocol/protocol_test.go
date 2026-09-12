package protocol

import (
	"encoding/base64"
	"encoding/json"
	"testing"
)

// The wire format of these payloads is a compatibility surface: agents and
// control planes are updated independently, so the JSON field names are
// asserted literally rather than only round-tripped.

func TestExecChunkWireFormat(t *testing.T) {
	in := ExecChunk{Stream: "stderr", DataB64: base64.StdEncoding.EncodeToString([]byte{0xff, 0x00, 'a'})}
	raw, err := json.Marshal(in)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	for _, k := range []string{"stream", "data_b64"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("ExecChunk JSON is missing %q: %s", k, raw)
		}
	}
	if len(fields) != 2 {
		t.Errorf("ExecChunk JSON has unexpected fields: %s", raw)
	}

	var out ExecChunk
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if out.Stream != in.Stream || out.DataB64 != in.DataB64 {
		t.Errorf("round trip = %+v, want %+v", out, in)
	}
	// Output is arbitrary bytes: base64 must survive non-UTF-8 intact.
	data, err := base64.StdEncoding.DecodeString(out.DataB64)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(data) != string([]byte{0xff, 0x00, 'a'}) {
		t.Errorf("payload corrupted: %v", data)
	}
}

func TestExecResultWireFormat(t *testing.T) {
	raw, err := json.Marshal(ExecResult{ExitCode: 3})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, ok := fields["exit_code"]; !ok {
		t.Errorf("ExecResult JSON is missing exit_code: %s", raw)
	}
	// error is omitempty: a successful command must not carry it.
	if _, ok := fields["error"]; ok {
		t.Errorf("empty error was serialized: %s", raw)
	}
	// A terminal result carries no output — output arrives as ExecChunk
	// frames. Re-adding these fields would silently double every result.
	for _, gone := range []string{"stdout", "stderr"} {
		if _, ok := fields[gone]; ok {
			t.Errorf("ExecResult JSON still carries %q: %s", gone, raw)
		}
	}
}

func TestExecStreamFrameWireFormat(t *testing.T) {
	exit := 0
	chunk := ExecStreamFrame{Type: ExecStreamChunk, Stream: "stdout", DataB64: "aGk="}
	raw, err := json.Marshal(chunk)
	if err != nil {
		t.Fatalf("marshal chunk: %v", err)
	}
	var fields map[string]json.RawMessage
	json.Unmarshal(raw, &fields)
	for _, k := range []string{"type", "stream", "data_b64"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("chunk frame is missing %q: %s", k, raw)
		}
	}
	// The exit record's fields must stay absent from a chunk, so a client can
	// switch on the presence of exit_code rather than trusting type alone.
	for _, gone := range []string{"exit_code", "error"} {
		if _, ok := fields[gone]; ok {
			t.Errorf("chunk frame carries %q: %s", gone, raw)
		}
	}

	done := ExecStreamFrame{Type: ExecStreamExit, ExitCode: &exit, Error: "boom"}
	raw, err = json.Marshal(done)
	if err != nil {
		t.Fatalf("marshal exit: %v", err)
	}
	fields = nil
	json.Unmarshal(raw, &fields)
	for _, k := range []string{"type", "exit_code", "error"} {
		if _, ok := fields[k]; !ok {
			t.Errorf("exit frame is missing %q: %s", k, raw)
		}
	}
	if _, ok := fields["data_b64"]; ok {
		t.Errorf("exit frame carries output: %s", raw)
	}
	// exit_code 0 is meaningful (success) and must not be dropped as empty.
	var back ExecStreamFrame
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("round trip: %v", err)
	}
	if back.ExitCode == nil || *back.ExitCode != 0 {
		t.Errorf("exit_code did not round-trip zero: %+v", back)
	}
	if back.Type != ExecStreamExit {
		t.Errorf("type = %q, want %q", back.Type, ExecStreamExit)
	}
}
