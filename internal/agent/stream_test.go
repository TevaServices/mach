package agent

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bcross/mach/internal/protocol"
	"github.com/gorilla/websocket"
)

// streamPipe gives the agent side of a websocket pair — the conn handleStream
// writes its frames to — plus the peer the test reads them from. Frames are
// exercised on the wire rather than mocked: the contract that matters is what
// the control plane receives.
func streamPipe(t *testing.T) (*protocol.WSConn, *websocket.Conn) {
	t.Helper()
	serverSide := make(chan *websocket.Conn, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := (&websocket.Upgrader{}).Upgrade(w, r, nil)
		if err != nil {
			return
		}
		serverSide <- c
	}))
	t.Cleanup(srv.Close)

	client, _, err := websocket.DefaultDialer.Dial("ws"+strings.TrimPrefix(srv.URL, "http"), nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { client.Close() })

	var server *websocket.Conn
	select {
	case server = <-serverSide:
	case <-time.After(5 * time.Second):
		t.Fatal("server side never connected")
	}
	return protocol.NewWSConn(server), client
}

// readEnvelope reads one frame, failing the test rather than hanging.
func readEnvelope(t *testing.T, peer *websocket.Conn) protocol.Envelope {
	t.Helper()
	_ = peer.SetReadDeadline(time.Now().Add(10 * time.Second))
	var env protocol.Envelope
	if err := peer.ReadJSON(&env); err != nil {
		t.Fatalf("read frame: %v", err)
	}
	return env
}

// collectStream reads frames until stream_end and returns the decoded stdout,
// stderr and the terminal record.
func collectStream(t *testing.T, peer *websocket.Conn) (stdout, stderr string, end protocol.StreamEnd) {
	t.Helper()
	var out, errOut strings.Builder
	for {
		env := readEnvelope(t, peer)
		switch env.Type {
		case "stream_out":
			var chunk protocol.StreamOut
			if err := json.Unmarshal(env.Payload, &chunk); err != nil {
				t.Fatalf("stream_out payload: %v", err)
			}
			b, err := base64.StdEncoding.DecodeString(chunk.B64)
			if err != nil {
				t.Fatalf("stream_out base64: %v", err)
			}
			if chunk.Stream == "stderr" {
				errOut.Write(b)
			} else {
				out.Write(b)
			}
		case "stream_end":
			if err := json.Unmarshal(env.Payload, &end); err != nil {
				t.Fatalf("stream_end payload: %v", err)
			}
			return out.String(), errOut.String(), end
		default:
			t.Fatalf("unexpected frame %q while streaming", env.Type)
		}
	}
}

// The agent's guardrail applies to a streaming session exactly as it does to a
// one-shot exec: the same rules, evaluated before anything is spawned.
func TestStreamRefusesDeniedCommand(t *testing.T) {
	globalPolicy.install("deny:stream-refused-marker\n")
	conn, peer := streamPipe(t)

	payload, _ := json.Marshal(protocol.StreamStart{Command: "echo stream-refused-marker"})
	handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-deny", Payload: payload},
		make(chan struct{}, 1), nil)

	env := readEnvelope(t, peer)
	if env.Type != "stream_end" {
		t.Fatalf("first frame = %q, want stream_end (nothing may run)", env.Type)
	}
	if env.ReqID != "sess-deny" {
		t.Errorf("req_id = %q, want the session id echoed back", env.ReqID)
	}
	var end protocol.StreamEnd
	if err := json.Unmarshal(env.Payload, &end); err != nil {
		t.Fatalf("stream_end payload: %v", err)
	}
	if end.ExitCode != 126 {
		t.Errorf("exit code = %d, want 126", end.ExitCode)
	}
	if !strings.Contains(end.Error, "deny:stream-refused-marker") {
		t.Errorf("refusal %q does not name the rule that refused it", end.Error)
	}
}

func TestStreamRunsAllowedCommandAndReportsExit(t *testing.T) {
	globalPolicy.install("")
	conn, peer := streamPipe(t)

	payload, _ := json.Marshal(protocol.StreamStart{Command: "echo streamed-hello; echo oops >&2; exit 7"})
	handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-run", Payload: payload},
		make(chan struct{}, 1), nil)

	stdout, stderr, end := collectStream(t, peer)
	if !strings.Contains(stdout, "streamed-hello") {
		t.Errorf("stdout = %q, want the command's output", stdout)
	}
	if !strings.Contains(stderr, "oops") {
		t.Errorf("stderr = %q, want the command's stderr", stderr)
	}
	// The exit status is a field of the terminal record, never text in the
	// output stream: nothing the command prints can become a control fact.
	if end.ExitCode != 7 {
		t.Errorf("exit code = %d, want 7 (got error %q)", end.ExitCode, end.Error)
	}
}

// argv mode goes straight to execve: no shell runs, so a byte-exact argument
// survives even when it looks like something a shell would expand.
func TestStreamArgvModeRunsNoShell(t *testing.T) {
	if runtimeGOOS() == "windows" {
		t.Skip("no portable echo binary on windows")
	}
	globalPolicy.install("")
	conn, peer := streamPipe(t)

	payload, _ := json.Marshal(protocol.StreamStart{Argv: []string{"echo", "$HOME"}})
	handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-argv", Payload: payload},
		make(chan struct{}, 1), nil)

	stdout, _, end := collectStream(t, peer)
	if strings.TrimSpace(stdout) != "$HOME" {
		t.Errorf("stdout = %q, want the literal $HOME — a shell expanded it", stdout)
	}
	if end.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", end.ExitCode)
	}
}

// A malformed start must end the session with a refusal rather than leaving the
// console waiting for output that will never come.
func TestStreamRejectsMalformedStart(t *testing.T) {
	conn, peer := streamPipe(t)

	handleStream(conn, protocol.Envelope{Type: "exec_stream", ReqID: "sess-bad", Payload: json.RawMessage(`"not an object"`)},
		make(chan struct{}, 1), nil)

	env := readEnvelope(t, peer)
	if env.Type != "stream_end" {
		t.Fatalf("frame = %q, want stream_end", env.Type)
	}
	var end protocol.StreamEnd
	_ = json.Unmarshal(env.Payload, &end)
	if end.ExitCode != 126 || end.Error == "" {
		t.Errorf("refusal = %+v, want exit 126 and a reason", end)
	}
}
