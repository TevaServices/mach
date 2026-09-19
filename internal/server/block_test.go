package server

// Tests for the operator's soft block and the non-reserving delete, across every
// path that dispatches to an agent.
//
// A block that one dispatch path forgets is not a block, so these cover both
// command paths (one-shot exec and the streaming relay), the hold on a queued
// update, and the property that is easiest to "fix" by mistake: the fleet policy
// mirror still reaches a blocked machine, because it is configuration rather
// than a command.

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/store"
	"github.com/gorilla/websocket"
)

// dialAgent completes the full agent handshake and returns the websocket. The
// relay harness connects an agent for you; these tests need to control *when* it
// connects (block first, then connect), so they drive the handshake themselves.
func dialAgent(t *testing.T, srvURL, mach, pubHex string, priv ed25519.PrivateKey) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srvURL, "http") + "/v1/agent/ws?name=" + mach
	ws, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { ws.Close() })

	var challenge protocol.Envelope
	if err := ws.ReadJSON(&challenge); err != nil {
		t.Fatalf("read challenge: %v", err)
	}
	if challenge.Type != "hello" {
		t.Fatalf("first frame = %q, want hello", challenge.Type)
	}
	sig := base64.StdEncoding.EncodeToString(ed25519.Sign(priv, []byte(mach+"|"+challenge.ReqID)))
	hello, _ := json.Marshal(protocol.HelloRequest{Auth: "v1 " + sig, PubKey: pubHex, Name: mach})
	if err := ws.WriteJSON(protocol.Envelope{Type: "hello", Payload: hello}); err != nil {
		t.Fatalf("write hello: %v", err)
	}
	var result protocol.Envelope
	if err := ws.ReadJSON(&result); err != nil {
		t.Fatalf("read hello_result: %v", err)
	}
	var hr protocol.HelloResponse
	_ = json.Unmarshal(result.Payload, &hr)
	if result.Type != "hello_result" || !hr.OK {
		t.Fatalf("hello refused: %q %s", result.Type, hr.Error)
	}
	return ws
}

// readAgentFrames pumps an agent socket into a channel until it closes.
func readAgentFrames(ws *websocket.Conn) <-chan protocol.Envelope {
	out := make(chan protocol.Envelope, 32)
	go func() {
		defer close(out)
		for {
			var env protocol.Envelope
			if err := ws.ReadJSON(&env); err != nil {
				return
			}
			select {
			case out <- env:
			default:
			}
		}
	}()
	return out
}

// framesWithin collects whatever arrives on a frame channel during d.
func framesWithin(frames <-chan protocol.Envelope, d time.Duration) []protocol.Envelope {
	var out []protocol.Envelope
	deadline := time.After(d)
	for {
		select {
		case env, ok := <-frames:
			if !ok {
				return out
			}
			out = append(out, env)
		case <-deadline:
			return out
		}
	}
}

func frameTypes(envs []protocol.Envelope) []string {
	var out []string
	for _, e := range envs {
		out = append(out, e.Type)
	}
	return out
}

// seedMachine enrolls a machine and returns its agent key pair.
func seedMachine(t *testing.T, st *store.Store, mach string) (pubHex string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	pubHex = hex.EncodeToString(pub)
	if err := st.CreateMachine(mach, pubHex, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed machine: %v", err)
	}
	return pubHex, priv
}

// A blocked machine is online, and the refusal has to say so. The regression
// this guards is the old behaviour of waiting 15s for the agent and then
// answering "machine offline or unknown" — true-sounding, and wrong.
func TestExecRefusedWhenMachineBlocked(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := st.SetMachineBlocked("bcross-a", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	key := adminKey(t, s, "exec:*")

	code, body := execReq(t, s, key, `{"machine":"bcross-a","command":"echo hi"}`)
	if code != http.StatusForbidden {
		t.Fatalf("blocked exec returned %d, want 403 (%s)", code, body)
	}
	// The reason must name the block, and must not claim the machine is offline.
	if !strings.Contains(body, "blocked") {
		t.Fatalf("refusal does not name the block: %s", body)
	}
	if strings.Contains(body, "offline") {
		t.Fatalf("refusal claims the machine is offline, but it is blocked: %s", body)
	}
	// The refusal preceded dispatch, so no machine-offline sentence is reachable.
	if strings.Contains(body, "unknown") {
		t.Fatalf("refusal claims the machine is unknown: %s", body)
	}

	// A block that silently swallowed commands would be indistinguishable in the
	// record from a machine that was simply idle, so the refusal is audited.
	entries, err := st.AuditList("bcross-a", 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("blocked exec left %d audit rows, want 1", len(entries))
	}
	if !entries[0].ExitCode.Valid || entries[0].ExitCode.Int64 != execRefused {
		t.Fatalf("refusal not audited as %d: %+v", execRefused, entries[0])
	}
	if !strings.Contains(entries[0].StderrSnip, "blocked") {
		t.Fatalf("audit row does not record why: %+v", entries[0])
	}
}

// Revoking a machine is meant to take it out of the fleet, and the dispatch
// path did not read the flag. `mach-server revoke-machine` runs in a *separate
// process*, so it cannot close this control plane's agent socket; the HTTP and
// UI paths do close it, so the gap was reachable only from the CLI — the one an
// operator would not think to check. The machine stays connected and keeps
// accepting exec, exec_stream, stream_stdin and stream_kill until it happens to
// reconnect, which for a healthy agent is never.
//
// The agent socket here is live on purpose: that is the whole condition.
func TestExecRefusedWhenMachineRevoked(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")

	// Revoked in the store, the way the CLI does it, with the socket left open.
	if err := h.st.RevokeMachine(h.mach); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if ac := h.s.br.Get(h.mach); ac == nil {
		t.Fatal("the agent socket was not left open; this test proves nothing")
	}

	code, body := execReq(t, h.s, key, fmt.Sprintf(`{"machine":%q,"command":"echo hi"}`, h.mach))
	if code != http.StatusForbidden {
		t.Fatalf("exec on a revoked machine returned %d, want 403 (%s)", code, body)
	}
	if !strings.Contains(body, "revoked") {
		t.Fatalf("the refusal does not name the revocation: %s", body)
	}
	// Audited like every other refusal, so the record shows the attempt.
	entries, err := h.st.AuditList(h.mach, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 || !entries[0].ExitCode.Valid || entries[0].ExitCode.Int64 != execRefused {
		t.Fatalf("revoked exec refusal not audited as %d: %+v", execRefused, entries)
	}

	// The streaming relay is a command path too: opening a session must be
	// refused rather than left to the per-frame check.
	if conn, _, resp := h.console(t, key, h.mach); conn != nil || resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("streaming on a revoked machine: conn=%v resp=%v, want 403", conn, resp)
	}
}

// A block set during the fifteen-second wait for the agent must not be
// dispatched anyway: "stop sending this machine commands" arriving one command
// too late is arriving at the command the operator was trying to prevent.
//
// The check used to happen only before the wait, so a request that parked there
// while the machine was offline had a window the streaming path never had (the
// relay re-checks every frame, so its window is microseconds). This drives the
// window for real: the exec is in flight and past its first check, the block
// lands, and only then does the agent come online so the wait returns.
func TestBlockSetDuringWaitOnlineStopsTheDispatch(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-late"
	pubHex, priv := seedMachine(t, st, mach)
	key := adminKey(t, s, "exec:*")

	type result struct {
		code int
		body string
	}
	ch := make(chan result, 1)
	go func() {
		// A one-second timeout, so a dispatch that slips through the window comes
		// back as a 504 in eleven seconds rather than holding the test open for
		// forty: the assertion below is then about the status, not about patience.
		code, body := execReq(t, s, key,
			fmt.Sprintf(`{"machine":%q,"command":"echo hi","timeout":1}`, mach))
		ch <- result{code, body}
	}()

	// Let the handler get past its first check — the machine is not blocked when
	// the request arrives, so that check passes — then block, then let the agent
	// connect and release the wait.
	time.Sleep(300 * time.Millisecond)
	if _, err := st.SetMachineBlocked(mach, true); err != nil {
		t.Fatalf("block: %v", err)
	}
	_ = dialAgent(t, srv.URL, mach, pubHex, priv)

	select {
	case r := <-ch:
		if r.code != http.StatusForbidden {
			t.Fatalf("a machine blocked mid-request was dispatched to: %d (%s)", r.code, r.body)
		}
		if !strings.Contains(r.body, "blocked") {
			t.Fatalf("refusal does not name the block: %s", r.body)
		}
	case <-time.After(25 * time.Second):
		t.Fatal("the exec never returned")
	}
}

// The negative control for the test above: the same request succeeds when the
// machine is not blocked, so the refusal is the block and not the request shape.
func TestExecAllowedWhenNotBlocked(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")
	code, body := execReq(t, h.s, key, fmt.Sprintf(`{"machine":%q,"command":"echo hi"}`, h.mach))
	if code != http.StatusOK {
		t.Fatalf("unblocked exec returned %d, want 200 (%s)", code, body)
	}
}

// The fleet listing still shows a blocked machine, flagged. Hiding it would make
// the operator's own action invisible — they could not see it to unblock it.
func TestMachinesReportsBlocked(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.CreateMachine("bcross-b", "pub-b", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := st.SetMachineBlocked("bcross-a", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	key := adminKey(t, s, "readonly")

	code, body := bearerJSON(t, s.Routes(), "GET", "/v1/machines", key, "")
	if code != http.StatusOK {
		t.Fatalf("machines: %d %s", code, body)
	}
	var resp protocol.MachinesResponse
	if err := json.Unmarshal([]byte(body), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(resp.Machines) != 2 {
		t.Fatalf("blocking removed a machine from the listing: %d rows", len(resp.Machines))
	}
	for _, m := range resp.Machines {
		want := m.Name == "bcross-a"
		if m.Blocked != want {
			t.Fatalf("machine %q blocked=%v, want %v", m.Name, m.Blocked, want)
		}
	}
}

// A queued update must survive the machine being blocked: the row is not merely
// left alone, it must not be popped at all, because the pop deletes it.
func TestBlockedAgentConnectHoldsQueuedUpdate(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-held"
	pubHex, priv := seedMachine(t, st, mach)
	if err := st.QueueUpdate(mach, "9.9.9", "sha", "", "ZGF0YQ==", "c2ln"); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if _, err := st.SetMachineBlocked(mach, true); err != nil {
		t.Fatalf("block: %v", err)
	}

	ws := dialAgent(t, srv.URL, mach, pubHex, priv)
	got := framesWithin(readAgentFrames(ws), 2*time.Second)

	if has, err := st.HasPendingUpdate(mach); err != nil || !has {
		t.Fatalf("blocked connect consumed the queued update: has=%v err=%v", has, err)
	}
	for _, env := range got {
		if env.Type == "update" {
			t.Fatalf("blocked machine was sent a queued update: %v", frameTypes(got))
		}
	}
	// The policy mirror is deliberately NOT gated — it is configuration, not a
	// command, and a blocked machine that missed a rule change would enforce
	// stale rules against sealed commands the moment it was unblocked.
	found := false
	for _, env := range got {
		if env.Type == "policy" {
			found = true
		}
	}
	if !found {
		t.Fatalf("blocked machine did not receive the fleet policy mirror: %v", frameTypes(got))
	}
}

// The negative control: an unblocked machine gets its queued update at connect,
// and the row is cleared.
func TestUnblockedAgentConnectDeliversQueuedUpdate(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-free"
	pubHex, priv := seedMachine(t, st, mach)
	if err := st.QueueUpdate(mach, "9.9.9", "sha", "", "ZGF0YQ==", "c2ln"); err != nil {
		t.Fatalf("queue: %v", err)
	}

	ws := dialAgent(t, srv.URL, mach, pubHex, priv)
	got := framesWithin(readAgentFrames(ws), 2*time.Second)
	found := false
	for _, env := range got {
		if env.Type == "update" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unblocked machine did not receive its queued update: %v", frameTypes(got))
	}
	if has, err := st.HasPendingUpdate(mach); err != nil || has {
		t.Fatalf("update not cleared after delivery: has=%v err=%v", has, err)
	}
}

// Unblocking a machine that is already online delivers the held update rather
// than making it wait for a reconnect that may never come. This is the second
// caller of PopPendingUpdate, so it also exercises the ordering that makes the
// pop single-delivery.
func TestUnblockDeliversHeldUpdateToLiveAgent(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-live"
	pubHex, priv := seedMachine(t, st, mach)
	if err := st.QueueUpdate(mach, "9.9.9", "sha", "", "ZGF0YQ==", "c2ln"); err != nil {
		t.Fatalf("queue: %v", err)
	}
	if _, err := st.SetMachineBlocked(mach, true); err != nil {
		t.Fatalf("block: %v", err)
	}
	ws := dialAgent(t, srv.URL, mach, pubHex, priv)
	frames := readAgentFrames(ws)
	if got := framesWithin(frames, 1500*time.Millisecond); len(got) == 0 {
		t.Fatal("agent received nothing at connect; cannot distinguish held from delivered")
	}

	if err := s.blockMachine(mach, false); err != nil {
		t.Fatalf("unblock: %v", err)
	}
	found := false
	for _, env := range framesWithin(frames, 2*time.Second) {
		if env.Type == "update" {
			found = true
		}
	}
	if !found {
		t.Fatal("unblocking did not deliver the held update to the live agent")
	}
}

// A blocked machine must not be able to open a streaming session at all, and it
// must be refused before the upgrade so the console gets a real HTTP status.
func TestStreamRefusedWhenBlocked(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")
	if err := h.s.blockMachine(h.mach, true); err != nil {
		t.Fatalf("block: %v", err)
	}
	_, _, resp := h.console(t, key, h.mach)
	if resp == nil {
		t.Fatal("a blocked machine accepted a streaming session")
	}
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("stream dial returned %d, want 403", resp.StatusCode)
	}
}

// A session opened before the block must not survive it: otherwise it could keep
// feeding stdin, or killing the running command, for as long as its console
// stayed connected — the opposite of a freeze.
func TestBlockEndsLiveStreamSession(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")
	console, _, resp := h.console(t, key, h.mach)
	if resp != nil {
		t.Fatalf("console dial refused: %d", resp.StatusCode)
	}

	execStream(t, console, "sleep 100")
	// The relay dispatched it, so a command really is running in this session.
	select {
	case env := <-h.frames:
		if env.Type != "exec_stream" {
			t.Fatalf("dispatched %q, want exec_stream", env.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec_stream never reached the agent")
	}

	if err := h.s.blockMachine(h.mach, true); err != nil {
		t.Fatalf("block: %v", err)
	}

	// The console is told why, and the socket is closed behind it.
	end := nextFrame(t, console)
	if end.Type != "stream_end" {
		t.Fatalf("console received %q, want stream_end", end.Type)
	}
	var se protocol.StreamEnd
	if err := json.Unmarshal(end.Payload, &se); err != nil {
		t.Fatalf("decode stream_end: %v", err)
	}
	if !strings.Contains(se.Error, "blocked") {
		t.Fatalf("stream_end does not explain the block: %q", se.Error)
	}

	// The session is unregistered, so it is not still sitting in the index.
	// Polled through the accessor (not the map) because the teardown that
	// unregisters it runs in the handler's own goroutine.
	waitFor(t, 3*time.Second, func() bool { return streamCountForMachine(h.mach) == 0 },
		"a stream session is still registered for a blocked machine")

	// And the teardown recorded the command as ending without an exit status —
	// the command is not cancelled by the console going away, so the row says
	// the fate is unknown rather than pretending it finished.
	waitFor(t, 3*time.Second, func() bool {
		entries, err := h.st.AuditList(h.mach, 10)
		if err != nil {
			return false
		}
		for _, e := range entries {
			if e.ExitCode.Valid && e.ExitCode.Int64 == -1 {
				return true
			}
		}
		return false
	}, "no -1 audit row for the killed stream")
}

// stdin and kill are gated too. Refusing only exec_stream would leave a session
// that can still feed a running command.
func TestStreamStdinRefusedWhenBlocked(t *testing.T) {
	h := newStreamHarness(t)
	key := adminKey(t, h.s, "exec:*")
	console, _, resp := h.console(t, key, h.mach)
	if resp != nil {
		t.Fatalf("console dial refused: %d", resp.StatusCode)
	}

	execStream(t, console, "cat")
	select {
	case env := <-h.frames:
		if env.Type != "exec_stream" {
			t.Fatalf("dispatched %q, want exec_stream", env.Type)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("exec_stream never reached the agent")
	}

	// Block mid-session, then try to feed the running command.
	if _, err := h.st.SetMachineBlocked(h.mach, true); err != nil {
		t.Fatalf("block: %v", err)
	}
	stdin, _ := json.Marshal(protocol.StreamStdin{B64: base64.StdEncoding.EncodeToString([]byte("hi\n"))})
	if err := console.WriteEnvelope(protocol.Envelope{Type: "stream_stdin", Payload: stdin}); err != nil {
		t.Fatalf("write stdin: %v", err)
	}

	// Nothing may reach the agent.
	if got := framesWithin(h.frames, 1500*time.Millisecond); len(got) != 0 {
		t.Fatalf("stdin was forwarded to a blocked machine: %v", frameTypes(got))
	}
}

// The admin surface requires the unrestricted exec:* key, exactly like revoke:
// these are fleet-wide actions, and an enroll key handed to a provisioning
// pipeline must never reach one.
func TestAdminBlockRequiresExecStar(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	body := `{"machine":"bcross-a","blocked":true}`
	for _, scopes := range []string{"enroll", "readonly", "exec:bcross-a"} {
		key := adminKey(t, s, scopes)
		code, resp := bearerJSON(t, s.Routes(), "POST", "/v1/admin/block", key, body)
		if code != http.StatusForbidden {
			t.Fatalf("scopes %q blocked a machine: %d (%s)", scopes, code, resp)
		}
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil || m.Blocked {
		t.Fatal("a scoped key changed the block state")
	}
	// The unrestricted key may.
	admin := adminKey(t, s, "exec:*")
	if code, resp := bearerJSON(t, s.Routes(), "POST", "/v1/admin/block", admin, body); code != http.StatusOK {
		t.Fatalf("exec:* could not block: %d (%s)", code, resp)
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil || !m.Blocked {
		t.Fatal("the block did not take effect")
	}
}

// An omitted "blocked" field must be a 400, not a silent unblock: a malformed
// request must never change a machine's state.
func TestAdminBlockRejectsMissingField(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if _, err := st.SetMachineBlocked("bcross-a", true); err != nil {
		t.Fatalf("block: %v", err)
	}
	admin := adminKey(t, s, "exec:*")
	code, _ := bearerJSON(t, s.Routes(), "POST", "/v1/admin/block", admin, `{"machine":"bcross-a"}`)
	if code != http.StatusBadRequest {
		t.Fatalf("missing blocked field returned %d, want 400", code)
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil || !m.Blocked {
		t.Fatal("a malformed request unblocked the machine")
	}
	// An unknown machine is a 404, not a silent success.
	code, _ = bearerJSON(t, s.Routes(), "POST", "/v1/admin/block", admin, `{"machine":"bcross-nope","blocked":true}`)
	if code != http.StatusNotFound {
		t.Fatalf("blocking an unknown machine returned %d, want 404", code)
	}
}

// Delete notifies the live agent so it can retire, then frees the name and key.
// The order matters: the row goes first, so a failed notification cannot leave a
// live authenticated socket for a machine that no longer exists.
func TestDeleteNotifiesAgentAndFreesName(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-gone"
	pubHex, priv := seedMachine(t, st, mach)
	ws := dialAgent(t, srv.URL, mach, pubHex, priv)
	frames := readAgentFrames(ws)

	admin := adminKey(t, s, "exec:*")
	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/admin/delete", admin,
		fmt.Sprintf(`{"machine":%q}`, mach))
	if code != http.StatusOK {
		t.Fatalf("delete returned %d (%s)", code, body)
	}

	got := framesWithin(frames, 2*time.Second)
	notified := false
	for _, env := range got {
		if env.Type == "deleted" {
			notified = true
		}
	}
	if !notified {
		t.Fatalf("agent was not told it was deleted: %v", frameTypes(got))
	}

	if m, _ := st.MachineByName(mach); m != nil {
		t.Fatal("machine row survived delete")
	}
	if m, _ := st.MachineByPubKey(pubHex); m != nil {
		t.Fatal("agent key survived delete")
	}
	// Deleting it again must be a clean 404: an operator retrying after a partial
	// failure needs to see the row is already gone, not a success that implies it
	// did something.
	code, _ = bearerJSON(t, s.Routes(), "POST", "/v1/admin/delete", admin,
		fmt.Sprintf(`{"machine":%q}`, mach))
	if code != http.StatusNotFound {
		t.Fatalf("deleting a missing machine returned %d, want 404", code)
	}
	// The name and the key material are free to enroll again — the recovery path
	// revocation deliberately cannot express.
	if err := st.CreateMachine(mach, pubHex, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("re-enroll with the freed name and key: %v", err)
	}
}

// waitFor polls a condition, because the relay's teardown writes its audit row
// from a goroutine that unwinds after the socket closes.
func waitFor(t *testing.T, d time.Duration, cond func() bool, msg string) {
	t.Helper()
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal(msg)
}

// Revoking and deleting end live console sessions, the way blocking does.
//
// The machine's own connection goes away with it, so a session left open has
// nowhere to send anything — it is a timeliness wart rather than a capability
// anyone keeps. But a session that still looks alive in the UI while the machine
// is out of the fleet is exactly the kind of thing an operator acts on, and
// block was the only one of the three that cleaned up after itself.
func TestRevokeAndDeleteEndLiveConsoleSessions(t *testing.T) {
	for _, action := range []string{"revoke", "delete"} {
		t.Run(action, func(t *testing.T) {
			h := newStreamHarness(t)
			key := adminKey(t, h.s, "exec:*")

			conn, _, resp := h.console(t, key, h.mach)
			if resp != nil {
				t.Fatalf("console dial refused: %s", resp.Status)
			}
			if n := streamCountForMachine(h.mach); n != 1 {
				t.Fatalf("sessions before the %s = %d, want 1", action, n)
			}

			switch action {
			case "revoke":
				if err := h.s.revokeMachine(h.mach, false); err != nil {
					t.Fatalf("revoke: %v", err)
				}
			case "delete":
				if err := h.s.deleteMachine(h.mach); err != nil {
					t.Fatalf("delete: %v", err)
				}
			}

			// The session is told why, and then the socket is closed under it.
			end := nextFrame(t, conn)
			if end.Type != "stream_end" {
				t.Fatalf("frame = %q, want a terminal record", end.Type)
			}
			var td protocol.StreamEnd
			_ = json.Unmarshal(end.Payload, &td)
			if !strings.Contains(td.Error, action) {
				t.Fatalf("terminal record says %q, want it to name the %s", td.Error, action)
			}
			deadline := time.Now().Add(5 * time.Second)
			for streamCountForMachine(h.mach) != 0 && time.Now().Before(deadline) {
				time.Sleep(5 * time.Millisecond)
			}
			if n := streamCountForMachine(h.mach); n != 0 {
				t.Fatalf("sessions after the %s = %d, want 0", action, n)
			}
		})
	}
}
