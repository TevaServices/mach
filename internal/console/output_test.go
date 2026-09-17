package console

// How a result reaches the terminal. A machine's output is bytes, and a JSON
// string cannot carry arbitrary ones, so this is where the exact-bytes form
// either survives the wire or does not.

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/bcross/mach/internal/protocol"
)

// Output that is not valid UTF-8 reaches the terminal as the bytes the machine
// produced. It cannot travel as a JSON string — Go's encoder replaces every
// invalid byte with U+FFFD, so a tarball came back mangled and longer — so it
// travels beside the text form, and the console prefers the exact bytes.
func TestPrintExecResultWritesExactBytesForBinaryOutput(t *testing.T) {
	raw := []byte{0x80, 0x00, 0xff, 'a', 0xc3} // not valid UTF-8
	var sent protocol.ExecResult
	sent.SetOutput(raw, []byte("plain stderr"))

	// Through the wire first. The loss happens at the JSON hop, not in the Go
	// string — an ExecResult built in this process still holds the bytes — so a
	// test that printed one directly would pass against a console that writes
	// the lossy text form.
	wire, err := protocol.MarshalResult(sent)
	if err != nil {
		t.Fatalf("MarshalResult: %v", err)
	}
	var res protocol.ExecResult
	if err := json.Unmarshal(wire, &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if res.Stdout == string(raw) {
		t.Fatal("the fixture survived the wire intact; it cannot test byte fidelity")
	}

	var code int
	stdout, stderr := capture(t, func() {
		code = printExecResult(&res, false)
	})
	if code != 0 {
		t.Errorf("code = %d, want 0", code)
	}
	if stdout != string(raw) {
		t.Errorf("stdout = %q (% x), want the exact bytes % x", stdout, stdout, raw)
	}
	if stderr != "plain stderr" {
		t.Errorf("stderr = %q, want the text form for valid UTF-8", stderr)
	}

	// --json carries both: the exact bytes for a program that wants them, and
	// the lossy text for one that reads the field it always did.
	var js protocol.ExecResult
	out, _ := capture(t, func() { printExecResult(&res, true) })
	if err := json.Unmarshal([]byte(out), &js); err != nil {
		t.Fatalf("--json output is not decodable: %v (%q)", err, out)
	}
	if got, want := js.StdoutB64, base64.StdEncoding.EncodeToString(raw); got != want {
		t.Errorf("stdout_b64 = %q, want %q", got, want)
	}
	if b, _ := js.Output(); string(b) != string(raw) {
		t.Errorf("a --json consumer decoding stdout_b64 got % x, want % x", b, raw)
	}
}
