package console

// How a result reaches the terminal. A machine's output is bytes, and a JSON
// string cannot carry arbitrary ones, so this is where the exact-bytes form
// either survives the wire or does not.

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/TevaServices/mach/internal/protocol"
)

// A machine's output is data, and the terminal is the one destination that
// *interprets* it. ESC]52 writes the operator's clipboard, OSC 0/8 rewrite the
// window title or forge a hyperlink, and CSI K/J erase what was already printed
// — which is how a compromised machine paints a fake `mach>` prompt, or a fake
// `mach: ` diagnostic, over what really happened. The console's candour that a
// human cannot tell machine output from mach diagnostics by content is about
// reading text; a sequence that redraws the screen is a different problem.
func TestEscapeSequencesAreNeutralizedOnATerminal(t *testing.T) {
	// A terminal destination: rewrite the ESC byte and nothing else.
	old := isTerminal
	isTerminal = func(*os.File) bool { return true }
	t.Cleanup(func() { isTerminal = old })

	hostile := "before\x1b]52;c;aGFjaw==\x07\x1b[2K\x1bmach: ok\nafter\n"
	got := string(safeForTerminal([]byte(hostile), os.Stdout))
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("an escape survived: %q", got)
	}
	// Everything that is not ESC is preserved, so the output is still readable
	// and still says what the machine said — just visibly.
	if !strings.Contains(got, "^[]52;c;aGFjaw==\x07") || !strings.Contains(got, "after\n") {
		t.Fatalf("the filter rewrote more than the ESC bytes: %q", got)
	}

	// A pipe gets the exact bytes, which is what invariant 9 promises and what a
	// program reading the output requires.
	isTerminal = func(*os.File) bool { return false }
	if got := string(safeForTerminal([]byte(hostile), os.Stdout)); got != hostile {
		t.Fatalf("a non-terminal destination was rewritten:\n got %q\nwant %q", got, hostile)
	}
	// And with nothing to filter, the destination is not even consulted.
	isTerminal = func(*os.File) bool { t.Fatal("the terminal check ran for output with no ESC"); return false }
	clean := "ls -la\ntotal 8\n"
	if got := string(safeForTerminal([]byte(clean), os.Stdout)); got != clean {
		t.Fatalf("clean output was rewritten: %q", got)
	}
}

// The agent-reported fields in the fleet table are a machine's own words too: a
// hostname is chosen by the machine, and it can contain an escape sequence.
func TestFleetTableSanitizesAgentReportedFields(t *testing.T) {
	old := isTerminal
	isTerminal = func(*os.File) bool { return true }
	t.Cleanup(func() { isTerminal = old })

	got := string(SafeForTerminal([]byte("web-01\x1b]0;pwned\x07")))
	if strings.ContainsRune(got, 0x1b) {
		t.Fatalf("a hostname's escape survived: %q", got)
	}
	if !strings.Contains(got, "web-01") {
		t.Fatalf("the hostname was mangled away: %q", got)
	}
}

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
