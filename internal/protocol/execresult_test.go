package protocol

// Tests for how a command's output is carried.
//
// The property is fidelity: what a machine printed is what a client writes out.
// Stdout and Stderr are JSON strings, and a JSON string must be valid UTF-8, so
// the text form is lossy by construction for anything else — which is why the
// exact bytes ride alongside it, and why it matters that they are used.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestOutputIsExactThroughTheTextFormWhenItIsUTF8(t *testing.T) {
	var r ExecResult
	r.SetOutput([]byte("unicode: ☃ é 日\n"), []byte("plain\n"))

	if r.StdoutB64 != "" || r.StderrB64 != "" {
		t.Fatalf("a valid UTF-8 result carried a base64 twin: %+v", r)
	}
	out, errOut := r.Output()
	if string(out) != "unicode: ☃ é 日\n" || string(errOut) != "plain\n" {
		t.Errorf("Output() = %q / %q, want the text back", out, errOut)
	}
}

// The bug this exists for: a command that cats a tarball came back mangled AND
// longer, because Go's encoder replaces each invalid byte with a 3-byte U+FFFD.
func TestBinaryOutputSurvivesExactly(t *testing.T) {
	raw := []byte{0x00, 0x80, 0xff, 0xfe, 'a', 0x1b, '[', '0', 'm'}
	var r ExecResult
	r.SetOutput(raw, nil)

	if r.StdoutB64 == "" {
		t.Fatal("binary output was not carried in its exact form")
	}
	out, _ := r.Output()
	if !bytes.Equal(out, raw) {
		t.Errorf("Output() = % x, want the exact bytes % x", out, raw)
	}

	// The loss is at the JSON hop, not in the Go string: a Go string holds any
	// bytes it likes, and the encoder is what coerces them to valid UTF-8. So the
	// test has to go through a real encode/decode to see it at all.
	wire, err := MarshalResult(r)
	if err != nil {
		t.Fatalf("MarshalResult: %v", err)
	}
	var back ExecResult
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatalf("decode: %v", err)
	}
	// The text form a client that does not know stdout_b64 would print: still
	// present, and now visibly not the bytes — longer, because each invalid byte
	// became the 3-byte replacement rune.
	if back.Stdout == string(raw) {
		t.Error("the text form claims to be the exact bytes; JSON cannot carry them")
	}
	if len(back.Stdout) <= len(raw) {
		t.Errorf("text form is %d bytes for %d bytes of input, want the replacement-rune inflation",
			len(back.Stdout), len(raw))
	}
	// And the bytes are still there for a client that asks for them.
	if got, _ := back.Output(); !bytes.Equal(got, raw) {
		t.Errorf("round trip = % x, want % x", got, raw)
	}
}

// A base64 field that will not decode yields no output rather than the lossy
// text beside it: printing that text would present corruption as the command's
// output, which is the failure this whole mechanism exists to avoid.
func TestUndecodableExactBytesDoNotFallBackToTheLossyText(t *testing.T) {
	r := ExecResult{Stdout: "��", StdoutB64: "!!! not base64 !!!"}
	if out, _ := r.Output(); out != nil {
		t.Errorf("Output() = %q, want nothing", out)
	}
	// The empty field is the other half: a result with no base64 twin uses its
	// text, including an empty text (a command that printed nothing).
	if out, _ := (ExecResult{Stdout: "text"}).Output(); string(out) != "text" {
		t.Errorf("Output() = %q, want the text form", out)
	}
}

// encoding/json escapes <, > and & by default. Every hop this JSON takes is
// somewhere that is never rendered as HTML, and the escaping inflated command
// output by up to 6× — part of how a result at the agent's own cap came to
// exceed the reply that had to carry it.
func TestMarshalResultDoesNotHTMLEscape(t *testing.T) {
	var r ExecResult
	r.SetOutput([]byte("a<b>&c</b>\n"), nil)

	wire, err := MarshalResult(r)
	if err != nil {
		t.Fatalf("MarshalResult: %v", err)
	}
	// The escaped form is what json.Marshal would have produced; its absence, and
	// the literal text's presence, are the same fact stated twice.
	if strings.Contains(string(wire), `\u003c`) || strings.Contains(string(wire), `\u0026`) {
		t.Errorf("output was HTML-escaped: %s", wire)
	}
	if !strings.Contains(string(wire), "a<b>&c</b>") {
		t.Errorf("angle brackets did not survive: %s", wire)
	}
	// Still valid JSON, and still decodes to the same bytes.
	var back ExecResult
	if err := json.Unmarshal(wire, &back); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if out, _ := back.Output(); string(out) != "a<b>&c</b>\n" {
		t.Errorf("round trip = %q", out)
	}
	// A quote still has to be escaped: this is JSON, not a licence to emit
	// whatever bytes we like.
	var q ExecResult
	q.SetOutput([]byte(`say "hi"`), nil)
	wire, _ = MarshalResult(q)
	if !json.Valid(wire) {
		t.Fatalf("MarshalResult produced invalid JSON: %s", wire)
	}
	var qb ExecResult
	if err := json.Unmarshal(wire, &qb); err != nil || qb.Stdout != `say "hi"` {
		t.Errorf("quotes did not round-trip: %q (%v)", qb.Stdout, err)
	}
}

// The two caps are different numbers on purpose, and this is the relationship
// that has to hold: the reply carrying a result is larger than the result, so a
// client cap equal to the agent's own made the truncation marker unreachable.
func TestReplyBoundExceedsTheAgentOutputCap(t *testing.T) {
	if MaxExecReplyBytes <= MaxOutputBytes {
		t.Fatalf("MaxExecReplyBytes (%d) must exceed MaxOutputBytes (%d)", MaxExecReplyBytes, MaxOutputBytes)
	}
	// Room for two streams, in both the text and the exact-bytes forms (the
	// latter at 4/3×), through the sealed envelope's base64 twice more (16/9×).
	want := int64(MaxOutputBytes) * 2 * 13 / 3 * 16 / 9
	if int64(MaxExecReplyBytes) < want {
		t.Errorf("MaxExecReplyBytes = %d, want at least %d to cover a full-cap sealed result", MaxExecReplyBytes, want)
	}
}
