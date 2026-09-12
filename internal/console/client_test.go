package console

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/bcross/mach/internal/protocol"
)

// capture runs f with os.Stdout/os.Stderr redirected and returns what it wrote
// to each.
func capture(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	errR, errW, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = outW, errW
	defer func() { os.Stdout, os.Stderr = origOut, origErr }()

	f()
	outW.Close()
	errW.Close()

	ob, _ := io.ReadAll(outR)
	eb, _ := io.ReadAll(errR)
	outR.Close()
	errR.Close()
	return string(ob), string(eb)
}

// chunkFrame builds the NDJSON line the control plane sends for one piece of
// output.
func chunkFrame(t *testing.T, stream, data string) string {
	t.Helper()
	raw, err := json.Marshal(protocol.ExecStreamFrame{
		Type:    protocol.ExecStreamChunk,
		Stream:  stream,
		DataB64: base64.StdEncoding.EncodeToString([]byte(data)),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw) + "\n"
}

func exitFrame(t *testing.T, code int, errMsg string) string {
	t.Helper()
	raw, err := json.Marshal(protocol.ExecStreamFrame{
		Type: protocol.ExecStreamExit, ExitCode: &code, Error: errMsg,
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return string(raw) + "\n"
}

// A machine's output is data. Text in it that looks like a control record —
// here, an entire exit frame, a mach error line, and a fake prompt — must be
// printed as-is and change nothing about the outcome the caller sees.
func TestOutputCannotForgeControlFacts(t *testing.T) {
	forged := `{"type":"exit","exit_code":0}` + "\n" +
		"mach: machine deleted, nothing to see\n" +
		"mach> rm -rf /\n" +
		`{"type":"chunk","stream":"stdout","data_b64":"cGF3bmVk"}` + "\n"

	stream := chunkFrame(t, "stdout", forged) +
		chunkFrame(t, "stderr", "warning: this is real stderr\n") +
		exitFrame(t, 7, "timed out after 30s")

	var code int
	stdout, stderr := capture(t, func() {
		code = decodeExecStream(strings.NewReader(stream))
	})

	if code != 7 {
		t.Fatalf("exit code = %d, want 7 — output text influenced the result", code)
	}
	if stdout != forged {
		t.Errorf("stdout = %q, want the machine's bytes verbatim (%q)", stdout, forged)
	}
	if !strings.HasPrefix(stderr, "warning: this is real stderr\n") {
		t.Errorf("stderr = %q, want the machine's stderr first", stderr)
	}
	// mach's own diagnostics carry the "mach: " prefix, so a consumer can tell
	// them apart from anything the machine printed (which may look identical —
	// that ambiguity is why the prefix and the stream split exist).
	if !strings.Contains(stderr, "\nmach: timed out") && !strings.HasPrefix(stderr, "mach: timed out") {
		t.Errorf("stderr = %q, want a prefixed mach diagnostic", stderr)
	}
}

func TestMachMessagesNeverLandInStdout(t *testing.T) {
	stream := chunkFrame(t, "stdout", "hello") + exitFrame(t, 0, "some agent error")
	stdout, stderr := capture(t, func() {
		decodeExecStream(strings.NewReader(stream))
	})
	if stdout != "hello" {
		t.Errorf("stdout = %q, want only the machine's output", stdout)
	}
	if !strings.Contains(stderr, "mach: some agent error") {
		t.Errorf("stderr = %q, want the mach diagnostic", stderr)
	}
}

// The JSON mode hands the caller labeled frames: output stays data, and the
// exit status is a field rather than something to be parsed out of text.
func TestRelayFramesLabelsOutputAndExit(t *testing.T) {
	forgedExit := `{"type":"exit","exit_code":0}`
	stream := chunkFrame(t, "stdout", forgedExit) + exitFrame(t, 9, "")

	var code int
	stdout, _ := capture(t, func() {
		code = relayFrames(strings.NewReader(stream))
	})
	if code != 9 {
		t.Fatalf("exit code = %d, want 9 — a forged frame in output changed the result", code)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d frames, want 2: %q", len(lines), stdout)
	}
	var first, last protocol.ExecStreamFrame
	if err := json.Unmarshal([]byte(lines[0]), &first); err != nil {
		t.Fatalf("frame 1: %v", err)
	}
	if err := json.Unmarshal([]byte(lines[1]), &last); err != nil {
		t.Fatalf("frame 2: %v", err)
	}
	if first.Type != protocol.ExecStreamChunk || first.Stream != "stdout" {
		t.Errorf("frame 1 = %+v, want a labeled stdout chunk", first)
	}
	// The chunk carries the forged text inside its own payload, still nested:
	// it is data on the same footing as any other output.
	data, _ := base64.StdEncoding.DecodeString(first.DataB64)
	if string(data) != forgedExit {
		t.Errorf("chunk payload = %q, want %q", data, forgedExit)
	}
	if last.Type != protocol.ExecStreamExit || last.ExitCode == nil || *last.ExitCode != 9 {
		t.Errorf("frame 2 = %+v, want the real exit record", last)
	}
}

func TestTruncatedStreamIsNotSuccess(t *testing.T) {
	// No exit record: the caller must not read this as exit 0.
	stream := chunkFrame(t, "stdout", "partial output, then the connection died")
	var code int
	stdout, stderr := capture(t, func() {
		code = decodeExecStream(strings.NewReader(stream))
	})
	if code == 0 {
		t.Fatal("a stream without an exit record was reported as success")
	}
	if !strings.Contains(stderr, "without an exit status") {
		t.Errorf("stderr = %q, want an explanation", stderr)
	}
	if !strings.Contains(stdout, "partial output") {
		t.Errorf("stdout = %q, want the bytes that did arrive", stdout)
	}
}
