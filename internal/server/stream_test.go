package server

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bcross/mach/internal/policy"
	"github.com/bcross/mach/internal/protocol"
	"github.com/bcross/mach/internal/store"
	"github.com/gorilla/websocket"
)

// streamHarness is a control plane with a real agent websocket attached, so the
// relay is exercised end to end: console → relay → agent pump → agent → relay →
// console. Everything the assertions below look at is what one of the two
// clients actually received.
type streamHarness struct {
	srv   *httptest.Server
	s     *Server
	st    *store.Store
	mach  string
	agent *websocket.Conn
	// frames carries the command-dispatch frames the fake agent was sent.
	// Connect-time bookkeeping (the fleet policy mirror) is delivered on its own
	// channel instead, so an assertion about what was dispatched is not
	// disturbed by what was merely synchronized.
	frames   chan protocol.Envelope
	policies chan protocol.PolicyUpdate
	// connectPolicy is the ruleset the control plane mirrored when this agent
	// connected. Consumed here so a test's own broadcasts are the only thing it
	// reads — and asserted, because "the rules arrive at connect" is the
	// property that makes them current on a machine that was offline when they
	// were configured.
	connectPolicy protocol.PolicyUpdate
}

// newStreamHarness enrolls a machine, drives a real agent hello over a real
// websocket, and answers one-shot execs so tests never wait on a timeout.
func newStreamHarness(t *testing.T) *streamHarness {
	t.Helper()
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-stream"
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex := hex.EncodeToString(pub)
	if err := st.CreateMachine(mach, pubHex, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed machine: %v", err)
	}

	wsURL := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/agent/ws?name=" + mach
	agent, _, err := websocket.DefaultDialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("agent dial: %v", err)
	}
	t.Cleanup(func() { agent.Close() })

	// Server challenge → signed hello → accepted.
	var challenge protocol.Envelope
	if err := agent.ReadJSON(&challenge); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if challenge.Type != "hello" {
		t.Fatalf("first frame = %q, want hello", challenge.Type)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(mach+"|"+challenge.ReqID)))
	hello, _ := json.Marshal(protocol.HelloRequest{Auth: "v1 " + sig, PubKey: pubHex, Name: mach})
	if err := agent.WriteJSON(protocol.Envelope{Type: "hello", Payload: hello}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	var result protocol.Envelope
	if err := agent.ReadJSON(&result); err != nil {
		t.Fatalf("read hello_result: %v", err)
	}
	var hr protocol.HelloResponse
	_ = json.Unmarshal(result.Payload, &hr)
	if result.Type != "hello_result" || !hr.OK {
		t.Fatalf("hello refused: %q %s", result.Type, hr.Error)
	}

	h := &streamHarness{
		srv: srv, s: s, st: st, mach: mach, agent: agent,
		frames:   make(chan protocol.Envelope, 16),
		policies: make(chan protocol.PolicyUpdate, 8),
	}
	// Play the agent: record what the control plane sends, and answer one-shot
	// execs so a test never waits out the dispatch grace period. Streaming
	// frames are left for the test to answer, since the point of those tests is
	// what the relay does with them.
	go func() {
		defer close(h.frames)
		for {
			var env protocol.Envelope
			if err := agent.ReadJSON(&env); err != nil {
				return
			}
			if env.Type == "policy" {
				var upd protocol.PolicyUpdate
				if json.Unmarshal(env.Payload, &upd) == nil {
					select {
					case h.policies <- upd:
					default:
					}
				}
				continue
			}
			select {
			case h.frames <- env:
			default:
			}
			if env.Type == "exec" {
				res, _ := json.Marshal(protocol.ExecResult{ExitCode: 0, Stdout: "ok\n"})
				_ = agent.WriteJSON(protocol.Envelope{Type: "exec_result", ReqID: env.ReqID, Payload: res})
			}
		}
	}()
	if ac := s.br.WaitOnline(mach, 5*time.Second); ac == nil {
		t.Fatal("agent never came online")
	}
	// The mirror is pushed immediately after the hello, so it is the agent's
	// first frame after hello_result. Waiting for it here is what lets a test
	// treat later pushes as its own.
	select {
	case h.connectPolicy = <-h.policies:
	case <-time.After(5 * time.Second):
		t.Fatal("the control plane did not mirror the fleet policy at connect")
	}
	return h
}

// console dials the streaming endpoint and consumes the relay's hello, which
// carries the session ID the agent's own frames must be tagged with. A refused
// dial returns the HTTP response instead.
func (h *streamHarness) console(t *testing.T, key, machine string) (conn *protocol.WSConn, sessionID string, resp *http.Response) {
	t.Helper()
	u := "ws" + strings.TrimPrefix(h.srv.URL, "http") + "/v1/console/stream?machine=" + machine
	hd := http.Header{}
	hd.Set("Authorization", "Bearer "+key)
	ws, resp, err := websocket.DefaultDialer.Dial(u, hd)
	if err != nil {
		return nil, "", resp
	}
	t.Cleanup(func() { ws.Close() })
	conn = protocol.NewWSConn(ws)
	hello := nextFrame(t, conn)
	if hello.Type != "stream_hello" {
		t.Fatalf("first frame = %q, want stream_hello", hello.Type)
	}
	return conn, hello.ReqID, nil
}

func execStream(t *testing.T, console *protocol.WSConn, command string) {
	t.Helper()
	payload, _ := json.Marshal(protocol.StreamStart{Command: command})
	if err := console.WriteEnvelope(protocol.Envelope{Type: "exec_stream", Payload: payload}); err != nil {
		t.Fatalf("write exec_stream: %v", err)
	}
}

// nextFrame reads one frame with a deadline, failing rather than hanging.
func nextFrame(t *testing.T, conn *protocol.WSConn) protocol.Envelope {
	t.Helper()
	type read struct {
		env protocol.Envelope
		err error
	}
	done := make(chan read, 1)
	go func() {
		env, err := conn.ReadEnvelope()
		done <- read{env, err}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("read frame: %v", r.err)
		}
		return r.env
	case <-time.After(5 * time.Second):
		t.Fatal("no frame arrived")
		return protocol.Envelope{}
	}
}

// A readonly key is for watching. The streaming endpoint is command execution,
// so it must refuse one — otherwise the scope would be decorative.
func TestStreamEndpointRefusesReadonlyKey(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "readonly")

	conn, _, resp := h.console(t, key, h.mach)
	if conn != nil {
		t.Fatal("readonly key was allowed to open a streaming session")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %v, want 403", resp)
	}
}

// A key scoped to another machine must not stream to this one.
func TestStreamEndpointRefusesUnscopedMachine(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:bcross-somewhere-else")

	conn, _, resp := h.console(t, key, h.mach)
	if conn != nil {
		t.Fatal("an unrelated key was allowed to open a streaming session")
	}
	if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %v, want 403", resp)
	}
}

// The fleet-wide block list covers streaming too: the same rule that stops a
// one-shot exec must stop the interactive path, or a client could bypass the
// block list by typing the command into the console instead.
func TestFleetPolicyBlocksStreamedCommand(t *testing.T) {
	h := newStreamHarness(t)
	h.s.execPolicy.Replace("deny:stream-blocked-marker\n", "test")
	key := adminKey(t, h.s, "exec:*")

	console, _, resp := h.console(t, key, h.mach)
	if console == nil {
		t.Fatalf("console dial failed: %v", resp)
	}
	execStream(t, console, "echo stream-blocked-marker")

	env := nextFrame(t, console)
	if env.Type != "stream_end" {
		t.Fatalf("frame = %q, want stream_end (nothing may be dispatched)", env.Type)
	}
	var end protocol.StreamEnd
	_ = json.Unmarshal(env.Payload, &end)
	if end.ExitCode != execRefused {
		t.Errorf("exit code = %d, want %d", end.ExitCode, execRefused)
	}
	if !strings.Contains(end.Error, "global exec policy") || !strings.Contains(end.Error, "deny:stream-blocked-marker") {
		t.Errorf("refusal = %q, want it to name the policy and the rule", end.Error)
	}
	// The command never reached the machine.
	select {
	case f := <-h.frames:
		t.Fatalf("blocked command was dispatched to the agent: %+v", f)
	case <-time.After(200 * time.Millisecond):
	}
	// And the attempt is in the record, not silently dropped.
	entries, err := h.st.AuditList(h.mach, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 || !strings.Contains(entries[0].Command, "stream-blocked-marker") {
		t.Fatalf("audit rows = %+v, want the blocked attempt recorded", entries)
	}
}

// E2E is a control plane setting, and the flag is the whole of it: with E2E off
// a sealed command is refused before dispatch, audited, and explained in the
// response so a client knows what to do instead of guessing from a console that
// silently ran in plaintext.
func TestSealedExecRefusedWhenE2EIsOff(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")
	sealed := `{"machine":"` + h.mach + `","sealed":"c2VhbGVk","e2e_pub":"ab","timeout":1}`

	// On (the default): relayed.
	if code, body := execReq(t, h.s, key, sealed); code == http.StatusForbidden {
		t.Fatalf("sealed exec refused while E2E is on: %d %s", code, body)
	}

	if err := SetE2E(h.st, "bcross", false); err != nil {
		t.Fatalf("set e2e off: %v", err)
	}
	code, body := execReq(t, h.s, key, sealed)
	if code != http.StatusForbidden {
		t.Fatalf("sealed exec with E2E off: %d %s, want 403", code, body)
	}
	if !strings.Contains(body, "disabled") || !strings.Contains(body, "mach-server e2e on") {
		t.Errorf("refusal = %q, want it to say the setting is off and how to change it", body)
	}
	// The attempt is in the record, and it never reached the machine.
	entries, err := h.st.AuditList(h.mach, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) == 0 || entries[0].Command != auditSealedLabel {
		t.Fatalf("audit rows = %+v, want the refused sealed attempt recorded", entries)
	}

	// Plaintext still runs: turning E2E off is not a way to stop commands, it
	// is a way to make them readable.
	if code, body := execReq(t, h.s, key, `{"machine":"`+h.mach+`","command":"echo hi","timeout":1}`); code != http.StatusOK {
		t.Errorf("plaintext exec refused while E2E is off: %d %s", code, body)
	}
}

// The stored setting is the deployment's answer; MACH_E2E is the operator
// pinning it from the environment, and a pin wins — otherwise a container spec
// could be contradicted by a row someone changed from a shell on the box.
func TestE2EEnvOverridesStoredSetting(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")
	sealed := `{"machine":"` + h.mach + `","sealed":"c2VhbGVk","e2e_pub":"ab","timeout":1}`

	t.Setenv("MACH_E2E", "off")
	if err := SetE2E(h.st, "bcross", true); err != nil {
		t.Fatalf("set e2e on: %v", err)
	}
	if code, body := execReq(t, h.s, key, sealed); code != http.StatusForbidden {
		t.Fatalf("stored on + MACH_E2E=off: %d %s, want 403 (the env pin must win)", code, body)
	}

	t.Setenv("MACH_E2E", "on")
	if err := SetE2E(h.st, "bcross", false); err != nil {
		t.Fatalf("set e2e off: %v", err)
	}
	if code, body := execReq(t, h.s, key, sealed); code == http.StatusForbidden {
		t.Fatalf("stored off + MACH_E2E=on: %d %s, want the sealed command relayed", code, body)
	}
}

// The control signal: what a client reads before it decides how to send a
// command. "The server will not accept ciphertext" and "this machine has no
// key" are different problems with different fixes, so they are different
// fields — a client that had to tell them apart from an error string would get
// it wrong eventually.
func TestE2EPubCarriesTheControlSignal(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")

	pub := func() (int, e2ePubResponse) {
		code, body := bearerJSON(t, h.s.Routes(), "GET", "/v1/machines/"+h.mach+"/e2epub", key, "")
		var resp e2ePubResponse
		if code == http.StatusOK {
			if err := json.Unmarshal([]byte(body), &resp); err != nil {
				t.Fatalf("e2epub body: %v (%s)", err, body)
			}
		}
		return code, resp
	}

	// E2E on, machine enrolled without a key: sealing is accepted, this machine
	// is the reason it cannot happen, and the note says so.
	code, resp := pub()
	if code != http.StatusOK {
		t.Fatalf("e2epub: %d", code)
	}
	if !resp.Enabled || resp.Mode != "on" {
		t.Errorf("signal = %+v, want E2E on", resp.E2EState)
	}
	if resp.PubE2E != "" || resp.Note == "" {
		t.Errorf("keyless machine = %+v, want no key and a note saying why", resp)
	}

	// With a key registered, the key is what comes back.
	const key64 = "9f2b1c4d5e6a7b8c9d0e1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e"
	withKey := "bcross-stream-keyed"
	if err := h.st.CreateMachine(withKey, "pub-keyed", "h", "linux", "amd64", "v", key64, false); err != nil {
		t.Fatalf("seed keyed machine: %v", err)
	}
	code2, body2 := bearerJSON(t, h.s.Routes(), "GET", "/v1/machines/"+withKey+"/e2epub", key, "")
	if code2 != http.StatusOK {
		t.Fatalf("e2epub keyed: %d %s", code2, body2)
	}
	var keyed e2ePubResponse
	if err := json.Unmarshal([]byte(body2), &keyed); err != nil {
		t.Fatalf("e2epub keyed body: %v", err)
	}
	if keyed.PubE2E != key64 || !keyed.Enabled {
		t.Errorf("keyed machine = %+v, want the registered key with sealing accepted", keyed)
	}

	// E2E off for this machine's org: the server says so, and advertises no key
	// at all — an obeying client does not seal to a key the server would refuse.
	if err := SetE2E(h.st, "bcross", false); err != nil {
		t.Fatalf("set e2e off: %v", err)
	}
	code, resp = pub()
	if code != http.StatusOK {
		t.Fatalf("e2epub with E2E off: %d", code)
	}
	if resp.Enabled || resp.Mode != "off" || resp.PubE2E != "" || resp.Reason == "" {
		t.Errorf("signal with E2E off = %+v, want off with a reason and no key", resp)
	}

	// The fleet listing carries the same answer per machine, so a client that
	// holds a machine name can decide without resolving its org itself.
	code, body := bearerJSON(t, h.s.Routes(), "GET", "/v1/machines", key, "")
	if code != http.StatusOK {
		t.Fatalf("machines: %d %s", code, body)
	}
	var list protocol.MachinesResponse
	if err := json.Unmarshal([]byte(body), &list); err != nil {
		t.Fatalf("machines body: %v", err)
	}
	seen := map[string]string{}
	for _, m := range list.Machines {
		seen[m.Name] = m.E2E
	}
	// Both machines are in org bcross, which was set off above: the listing has
	// to agree with the per-machine signal the client acts on.
	for _, name := range []string{h.mach, withKey} {
		if seen[name] != "off" {
			t.Errorf("listing e2e for %s = %q, want off", name, seen[name])
		}
	}
}

// The setting is per org: one team turning sealing off must not turn it off for
// the next team, and must not be talked out of it by a fleet-wide row.
//
// Resolution is asserted through the state the server actually consults rather
// than by issuing an exec per case: an exec to an offline machine waits out the
// dispatch grace period, and the matrix is the point here. The HTTP refusal
// path itself is covered by TestSealedExecRefusedWhenE2EIsOff.
func TestE2EIsPerOrg(t *testing.T) {
	h := newStreamHarness(t)
	t.Setenv("MACH_ORGS", "acme")
	key := adminKey(t, h.s, "exec:*")

	const acme = "acme-web-01"
	if err := h.st.CreateMachine(acme, "pub-acme", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed acme machine: %v", err)
	}
	enabled := func(machine string) bool { return h.s.e2eStateFor(machine).Enabled }

	// Both orgs start on the default.
	if !enabled(h.mach) || !enabled(acme) {
		t.Fatalf("default = bcross:%v acme:%v, want both on", enabled(h.mach), enabled(acme))
	}

	// Off for acme only: bcross is untouched, because it is a different org's
	// decision.
	if err := SetE2E(h.st, "acme", false); err != nil {
		t.Fatalf("set acme off: %v", err)
	}
	if enabled(acme) {
		t.Error("acme is still on after being set off")
	}
	if !enabled(h.mach) {
		t.Error("bcross was affected by acme's setting")
	}
	// The refusal names the org, so a console can say which one to ask about.
	code, body := execReq(t, h.s, key, `{"machine":"`+acme+`","sealed":"c2VhbGVk","e2e_pub":"ab","timeout":1}`)
	if code != http.StatusForbidden || !strings.Contains(body, "acme") {
		t.Errorf("acme sealed exec = %d %q, want 403 naming the org", code, body)
	}

	// A default row applies to every org without its own setting — and not to
	// the org that has one.
	if err := SetE2E(h.st, "", false); err != nil {
		t.Fatalf("set default off: %v", err)
	}
	if enabled(h.mach) {
		t.Error("bcross is still on under an off default")
	}
	if enabled(acme) {
		t.Error("acme's own on-setting was overridden by the default")
	}
	// Dropping acme's override makes it follow the default again.
	if err := ClearE2E(h.st, "acme"); err != nil {
		t.Fatalf("clear acme: %v", err)
	}
	if enabled(acme) {
		t.Error("acme did not inherit the off default after its override was removed")
	}
	// Re-enable acme specifically: it is on again while the default stays off.
	if err := SetE2E(h.st, "acme", true); err != nil {
		t.Fatalf("set acme on: %v", err)
	}
	if !enabled(acme) {
		t.Error("acme's own on-setting did not win over the off default")
	}
	if enabled(h.mach) {
		t.Error("bcross is on despite the off default")
	}
}

// A machine whose org cannot be resolved from the configured prefixes falls
// back to the default. It must not borrow another org's answer, which would be
// a silent way to run under a setting nobody chose for it.
func TestE2EUnknownOrgFallsBackToTheDefault(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")

	// An org that is not configured on this server.
	const orphan = "unconfigured-01"
	if err := h.st.CreateMachine(orphan, "pub-orphan", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed orphan machine: %v", err)
	}
	// bcross (the configured org) is turned off; the orphan must not inherit it.
	if err := SetE2E(h.st, "bcross", false); err != nil {
		t.Fatalf("set bcross off: %v", err)
	}
	if st := h.s.e2eStateFor(orphan); !st.Enabled {
		t.Errorf("unresolvable org used another org's setting: %+v", st)
	}
	if st := h.s.e2eStateFor(orphan); st.Org != "" {
		t.Errorf("unresolvable org reported as %q, want no org", st.Org)
	}
	// When the default is off, that is what governs it — and the refusal path
	// agrees (it is refused before dispatch, so no offline wait).
	if err := SetE2E(h.st, "", false); err != nil {
		t.Fatalf("set default off: %v", err)
	}
	if h.s.e2eStateFor(orphan).Enabled {
		t.Error("unresolvable org is on under an off default")
	}
	code, body := execReq(t, h.s, key, `{"machine":"`+orphan+`","sealed":"c2VhbGVk","e2e_pub":"ab","timeout":1}`)
	if code != http.StatusForbidden {
		t.Errorf("unresolvable org with an off default: %d %s, want 403", code, body)
	}
}

// E2E on is not a licence to run unchecked plaintext: the fleet-wide block list
// keeps checking every command it can read, on both paths. Turning E2E off is
// how an operator gets the block list over the one-shot path too — not a
// precondition for the block list to work at all.
func TestFleetPolicyChecksPlaintextWhileE2EIsOn(t *testing.T) {
	h := newStreamHarness(t)
	h.s.execPolicy.Replace("deny:plain-marker\n", "test")
	key := adminKey(t, h.s, "exec:*")

	code, body := execReq(t, h.s, key, `{"machine":"`+h.mach+`","command":"echo plain-marker","timeout":1}`)
	if code != http.StatusForbidden || !strings.Contains(body, "deny:plain-marker") {
		t.Fatalf("plaintext exec with E2E on: %d %s, want the block list to refuse it", code, body)
	}
}

// A streamed command leaves the same evidence a buffered one does. Without this
// a control plane could relay commands the audit trail never mentions.
func TestStreamedCommandIsAudited(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")
	console, sessionID, resp := h.console(t, key, h.mach)
	if console == nil {
		t.Fatalf("console dial failed: %v", resp)
	}
	execStream(t, console, "echo audited-marker")

	// The relay forwarded it to the machine, tagged with the session.
	select {
	case f := <-h.frames:
		if f.Type != "exec_stream" {
			t.Fatalf("agent got %q, want exec_stream", f.Type)
		}
		if f.ReqID != sessionID {
			t.Fatalf("agent frame req_id = %q, want the session id %q", f.ReqID, sessionID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the command never reached the agent")
	}

	// Play the agent: stream some output, then report the exit status.
	out, _ := json.Marshal(protocol.StreamOut{Stream: "stdout", B64: base64.StdEncoding.EncodeToString([]byte("audited-marker\n"))})
	end, _ := json.Marshal(protocol.StreamEnd{ExitCode: 7})
	for _, env := range []protocol.Envelope{
		{Type: "stream_out", ReqID: sessionID, Payload: out},
		{Type: "stream_end", ReqID: sessionID, Payload: end},
	} {
		if err := h.agent.WriteJSON(env); err != nil {
			t.Fatalf("agent write: %v", err)
		}
	}

	sawOut := false
	for i := 0; i < 3; i++ {
		env := nextFrame(t, console)
		if env.Type == "stream_out" {
			sawOut = true
			continue
		}
		if env.Type == "stream_end" {
			var e protocol.StreamEnd
			_ = json.Unmarshal(env.Payload, &e)
			if e.ExitCode != 7 {
				t.Errorf("exit code = %d, want 7", e.ExitCode)
			}
			break
		}
	}
	if !sawOut {
		t.Error("console never received the streamed output")
	}

	deadline := time.Now().Add(2 * time.Second)
	for {
		entries, err := h.st.AuditList(h.mach, 10)
		if err != nil {
			t.Fatalf("audit list: %v", err)
		}
		if len(entries) > 0 {
			e := entries[0]
			if !strings.Contains(e.Command, "audited-marker") {
				t.Errorf("audit command = %q, want the streamed command", e.Command)
			}
			if !e.ExitCode.Valid || e.ExitCode.Int64 != 7 {
				t.Errorf("audit exit code = %+v, want 7", e.ExitCode)
			}
			if !strings.Contains(e.StdoutSnip, "audited-marker") {
				t.Errorf("audit stdout = %q, want the head of the output", e.StdoutSnip)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the streamed command left no audit row")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The fleet-wide block list has to reach the machines, because that is the only
// place a sealed command is readable. This checks the mirror itself: the rules
// are pushed at connect (even when empty, which is a real instruction), and the
// agent's acknowledgement of the version is recorded.
func TestFleetPolicyIsMirroredToAgents(t *testing.T) {
	h := newStreamHarness(t)
	h.s.execPolicy.Replace("deny:mirror-marker\nallowonly\n", "test")

	// The connect-time mirror carried the ruleset as it stood then (none): the
	// harness asserts it arrived, and here it is checked to be empty rather than
	// a stale ruleset from some earlier state.
	if h.connectPolicy.Rules != "" {
		t.Errorf("connect-time ruleset = %q, want empty", h.connectPolicy.Rules)
	}

	// A change is broadcast to every live agent, because the rules run on the
	// machines: a change that only updated this process would leave every
	// running agent enforcing the previous version until it reconnected.
	h.s.broadcastFleetPolicy()

	want := policy.Fingerprint("deny:mirror-marker\nallowonly")
	select {
	case upd := <-h.policies:
		if upd.Rules != "deny:mirror-marker\nallowonly" {
			t.Errorf("rules = %q, want the spec text", upd.Rules)
		}
		if upd.Version != want {
			t.Errorf("version = %q, want the fingerprint %q", upd.Version, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the fleet policy never reached the agent")
	}

	// Withdrawing the policy sends an empty ruleset. That is an instruction, not
	// an absence: a machine that kept enforcing withdrawn rules would be a block
	// list nobody can turn off.
	h.s.execPolicy.Replace("", "test")
	h.s.broadcastFleetPolicy()
	select {
	case upd := <-h.policies:
		if upd.Rules != "" || upd.Version != policy.Fingerprint("") {
			t.Errorf("cleared policy pushed %+v, want an empty ruleset and its fingerprint", upd)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the cleared policy never reached the agent")
	}
	h.s.execPolicy.Replace("deny:mirror-marker\nallowonly\n", "test")
	h.s.broadcastFleetPolicy()
	select {
	case <-h.policies:
	case <-time.After(5 * time.Second):
		t.Fatal("the restored policy never reached the agent")
	}

	// The agent acks; the control plane records what it is enforcing. Without
	// the ack, "which machines hold the current rules" has no answer.
	ack, _ := json.Marshal(protocol.PolicyAck{Version: want})
	if err := h.agent.WriteJSON(protocol.Envelope{Type: "policy_ack", Payload: ack}); err != nil {
		t.Fatalf("write ack: %v", err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for {
		if got := h.s.policyAck(h.mach); got == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("ack for %q was not recorded (got %q)", want, h.s.policyAck(h.mach))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// A policy file edited on disk has to reach machines that are already connected.
// The rules run on the machines, so a reload that updated only this process
// would leave every running agent enforcing the withdrawn rules until it
// happened to reconnect — a block list that quietly stops applying to the
// machines it was written for.
func TestPolicyFileReloadReachesConnectedAgents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fleet.policy")
	if err := os.WriteFile(path, []byte("deny:first-marker\n"), 0o600); err != nil {
		t.Fatalf("write policy: %v", err)
	}
	t.Setenv(execPolicyFileEnv, path)

	h := newStreamHarness(t)
	if got, want := h.connectPolicy.Rules, "deny:first-marker"; got != want {
		t.Fatalf("connect-time ruleset = %q, want %q", got, want)
	}

	// Edit the file the way an operator would, and make sure the mtime moves
	// even on a filesystem with coarse timestamps.
	if err := os.WriteFile(path, []byte("deny:first-marker\ndeny:second-marker\n"), 0o600); err != nil {
		t.Fatalf("edit policy: %v", err)
	}
	future := time.Now().Add(2 * time.Second)
	if err := os.Chtimes(path, future, future); err != nil {
		t.Fatalf("chtimes: %v", err)
	}

	want := "deny:first-marker\ndeny:second-marker"
	// What the ticker does on every interval, driven directly: the ticker is
	// three lines of stdlib, the reload-and-propagate path is the part that can
	// be wrong, and this way it is asserted without waiting one out. (The e2e
	// suite exercises the real interval against real binaries.)
	h.s.pollPolicyOnce()
	select {
	case upd := <-h.policies:
		if upd.Rules != want {
			t.Errorf("pushed ruleset = %q, want %q", upd.Rules, want)
		}
		if upd.Version != policy.Fingerprint(want) {
			t.Errorf("pushed version = %q, want the fingerprint of the new rules", upd.Version)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("an edited policy file never reached the connected agent")
	}
	// A second poll with nothing changed pushes nothing: a control plane that
	// re-broadcast on every tick would keep waking every agent in the fleet.
	h.s.pollPolicyOnce()
	select {
	case upd := <-h.policies:
		t.Errorf("an unchanged policy was pushed again: %+v", upd)
	case <-time.After(100 * time.Millisecond):
	}
}

// One session carries one command, because the agent tags every output frame and
// the terminal record with the SESSION id — two commands interleaved on one
// connection cannot be told apart. Pipelining a second exec_stream used to
// overwrite the running command's identity, which wrote a single audit row
// naming the second command with the FIRST command's exit code and no row at all
// for the first: a command could be hidden from the trail by sending it behind
// one that was already running.
func TestSecondCommandInOneSessionIsRefused(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")
	console, sessionID, resp := h.console(t, key, h.mach)
	if console == nil {
		t.Fatalf("console dial failed: %v", resp)
	}

	execStream(t, console, "echo first-marker")
	select {
	case f := <-h.frames:
		if f.Type != "exec_stream" {
			t.Fatalf("agent got %q, want exec_stream", f.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the first command never reached the agent")
	}

	// A second command while the first is still running.
	execStream(t, console, "echo second-marker")
	env := nextFrame(t, console)
	if env.Type != "stream_end" {
		t.Fatalf("second command frame = %q, want a stream_end refusal", env.Type)
	}
	var end protocol.StreamEnd
	_ = json.Unmarshal(env.Payload, &end)
	if end.ExitCode != execRefused {
		t.Errorf("refusal exit = %d, want %d", end.ExitCode, execRefused)
	}
	if !strings.Contains(end.Error, "already running") {
		t.Errorf("refusal %q does not say why", end.Error)
	}

	// Nothing was dispatched to the machine for it.
	select {
	case f := <-h.frames:
		t.Fatalf("the refused command was dispatched anyway: %q", f.Type)
	case <-time.After(200 * time.Millisecond):
	}

	// The first command still finishes and is audited under its own name.
	end1, _ := json.Marshal(protocol.StreamEnd{ExitCode: 3})
	if err := h.agent.WriteJSON(protocol.Envelope{Type: "stream_end", ReqID: sessionID, Payload: end1}); err != nil {
		t.Fatalf("agent write: %v", err)
	}
	// The refusal is audited immediately, so wait for the RUNNING command's row
	// specifically rather than for "any row at all".
	deadline := time.Now().Add(3 * time.Second)
	for {
		entries, err := h.st.AuditList(h.mach, 10)
		if err != nil {
			t.Fatalf("audit list: %v", err)
		}
		var first, second *store.AuditEntry
		for i := range entries {
			switch {
			case strings.Contains(entries[i].Command, "first-marker"):
				first = &entries[i]
			case strings.Contains(entries[i].Command, "second-marker"):
				second = &entries[i]
			}
		}
		if first != nil {
			if !first.ExitCode.Valid || first.ExitCode.Int64 != 3 {
				t.Errorf("first command audited as %+v, want exit 3 under its own name", first.ExitCode)
			}
			if second == nil {
				t.Fatal("the refused command was not audited")
			}
			if !second.ExitCode.Valid || second.ExitCode.Int64 != execRefused {
				t.Errorf("refused command audited as %+v, want %d", second.ExitCode, execRefused)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the running command left no audit row (%d rows seen)", len(entries))
		}
		time.Sleep(20 * time.Millisecond)
	}
}
