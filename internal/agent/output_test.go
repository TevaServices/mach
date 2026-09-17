package agent

// Where a command's output goes, and how it is shaped on the way to the wire.

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/bcross/mach/internal/protocol"
)

// A command's output reaches the wire as the bytes it produced, and a truncated
// stream says so in both forms.
//
// The two are one test because they are one mechanism: cappedBuffer.Bytes has to
// carry the same truncation marker String does, or the bytes we hand the wire and
// the text we show would disagree about where the stream ended.
func TestCommandOutputKeepsItsBytesAndItsTruncationMarker(t *testing.T) {
	globalPolicy.install("")
	conn, peer := streamPipe(t)

	// A shell that can emit a byte no JSON string can hold.
	raw := []byte{0x00, 0x80, 0xff}
	payload, _ := json.Marshal(protocol.ExecCommand{
		Argv: []string{"/bin/sh", "-c", `printf '\000\200\377'`}, Timeout: 5,
	})
	go handleExec(conn, protocol.Envelope{Type: "exec", ReqID: "bytes-1", Payload: payload},
		make(chan struct{}, 1), nil)

	env := readEnvelope(t, peer)
	if env.Type != "exec_result" {
		t.Fatalf("frame = %q, want exec_result", env.Type)
	}
	var res protocol.ExecResult
	if err := json.Unmarshal(env.Payload, &res); err != nil {
		t.Fatalf("result payload: %v", err)
	}
	got, _ := res.Output()
	if !bytes.Equal(got, raw) {
		t.Errorf("output = % x, want the exact bytes % x (text form was %q)", got, raw, res.Stdout)
	}
	if res.StdoutB64 == "" {
		t.Error("binary output was sent without its exact-bytes field")
	}

	// A stream over the cap is truncated and marked — in the text form and in the
	// bytes, which is what a client that reads either one sees.
	var buf cappedBuffer
	buf.max = 16
	_, _ = buf.Write([]byte("0123456789abcdefOVERFLOW"))
	if b := buf.Bytes(); !strings.Contains(string(b), "[mach: output truncated at cap]") {
		t.Errorf("Bytes() = %q, want the truncation marker", b)
	}
	if b := buf.Bytes(); !strings.HasPrefix(string(b), "0123456789abcdef") {
		t.Errorf("Bytes() = %q, want the cap's worth of output first", b)
	}
	if buf.String() != string(buf.Bytes()) {
		t.Errorf("String() = %q and Bytes() = %q disagree about the stream",
			buf.String(), buf.Bytes())
	}
}
