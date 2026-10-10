package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
)

// TestPlaintextExecRelayCarriesInjectEnv pins the relay half of plaintext
// secret injection. The agent side (resolveInjection against the machine's
// local store, output scrubbing) is pinned in agent secrets_test.go with a
// hand-built ExecCommand frame; the server side had no pin, and the plaintext
// relay dropped InjectEnv entirely — sealed exec (whose names travel inside
// the seal) injected fine while every plaintext exec — mach exec --no-e2e,
// and the MCP exec tool's only path, which is always plaintext — ran with
// empty variables. The names were never in doubt server-side: the request
// carries them and the injectRefusal gate above the dispatch validates them
// against the registry. This test drives a real dispatch through a fake
// agent connection and asserts the outbound exec frame carries the names.
func TestPlaintextExecRelayCarriesInjectEnv(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.UpsertSecret("bcross", "DB_PASSWORD", "test"); err != nil {
		t.Fatalf("register secret: %v", err)
	}
	pubHex, priv := seedMachine(t, st, "bcross-a", "bcross")
	key := adminKey(t, s, "exec:*")
	ts := httptest.NewServer(s.Routes())
	t.Cleanup(ts.Close)
	ws := dialAgent(t, ts.URL, "bcross-a", pubHex, priv)
	frames := readAgentFrames(ws)

	type result struct {
		code int
		body string
	}
	done := make(chan result, 1)
	go func() {
		// The HTTP API carries the names as inject_env (the MCP tool's
		// `inject` argument is the adapter's spelling of the same list).
		code, body := execReq(t, s, key, `{"machine":"bcross-a","command":"echo hi","inject_env":["DB_PASSWORD"],"timeout":10}`)
		done <- result{code, body}
	}()

	deadline := time.After(10 * time.Second)
	var reqID string
	for reqID == "" {
		select {
		case env := <-frames:
			if env.Type != "exec" {
				continue // policy pushes and other connect-time frames
			}
			var cmd protocol.ExecCommand
			if err := json.Unmarshal(env.Payload, &cmd); err != nil {
				t.Fatalf("exec frame payload: %v", err)
			}
			if len(cmd.InjectEnv) != 1 || cmd.InjectEnv[0] != "DB_PASSWORD" {
				t.Fatalf("plaintext exec frame carries InjectEnv %v, want [DB_PASSWORD] — the relay dropped the names", cmd.InjectEnv)
			}
			reqID = env.ReqID
		case <-deadline:
			t.Fatal("no exec frame within 10s")
		}
	}
	// Reply so the pending handler completes; the agent-side resolution is
	// the agent test's job, this one ends at the frame.
	reply, _ := json.Marshal(protocol.ExecResult{ExitCode: 0, Stdout: "hi"})
	if err := ws.WriteJSON(protocol.Envelope{Type: "exec_result", ReqID: reqID, Payload: reply}); err != nil {
		t.Fatalf("write exec_result: %v", err)
	}
	res := <-done
	if res.code != http.StatusOK {
		t.Fatalf("exec: %d %s", res.code, res.body)
	}
}
