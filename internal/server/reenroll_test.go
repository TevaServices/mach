package server

// Tests for re-enrollment after revocation.
//
// Revocation is a forced re-enrollment, not a permanent ban: the agent
// self-retires, the name and key stay reserved, and the machine comes back only
// through a fresh enrollment — which needs an enroll key or a phone approval, so
// it is still operator-gated.
//
// The counterweight, tested here as hard as the feature itself: an ACTIVELY
// enrolled machine is never displaced. Its name and its key stay its own, which
// is what stops a typo (or a hostile enrollee) from taking over a working agent.

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
	"github.com/gorilla/websocket"
)

func newKeyHex(t *testing.T) (pubHex string, priv ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	return hex.EncodeToString(pub), priv
}

func enrollBody(key, pubHex, name string) string {
	return fmt.Sprintf(`{"api_key":%q,"pub_key":%q,"name":%q}`, key, pubHex, name)
}

// dialAgentExpectRefusal dials the agent endpoint WITHOUT attempting a hello,
// and returns the socket so a caller can see what an unauthenticated client is
// told. Since the control plane now sends the challenge first and says nothing
// else until it has verified a signature, what such a client sees is the
// challenge and then silence — for every name, which is the point.
func dialAgentExpectRefusal(t *testing.T, srvURL, mach string) *websocket.Conn {
	t.Helper()
	u := "ws" + strings.TrimPrefix(srvURL, "http") + "/v1/agent/ws?name=" + mach
	ws, _, err := websocket.DefaultDialer.Dial(u, nil)
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { ws.Close() })
	return ws
}

// dialAgentHello performs the whole challenge/hello exchange and hands back the
// reply without asserting what it says, so a test can check a refusal. Unlike
// dialAgent it does not require the machine to be accepted.
func dialAgentHello(t *testing.T, srvURL, mach, pubHex string, priv ed25519.PrivateKey) (*websocket.Conn, protocol.HelloResponse) {
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
	return ws, hr
}

// The whole point: a revoked machine comes back through a fresh enrollment.
func TestReEnrollmentRevivesARevokedMachine(t *testing.T) {
	s, st := newAuthTestServer(t)
	oldPub, _ := newKeyHex(t)
	if err := st.CreateMachine("bcross-web", oldPub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.RevokeMachine("bcross-web"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Re-enroll with a NEW key under the SAME name — what a temporary session
	// does, since it holds no key across runs.
	newPub, _ := newKeyHex(t)
	key := adminKey(t, s, "enroll")
	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "", enrollBody(key, newPub, "bcross-web"))
	if code != http.StatusOK {
		t.Fatalf("re-enrollment returned %d, want 200 (%s)", code, body)
	}

	m, err := st.MachineByName("bcross-web")
	if err != nil || m == nil {
		t.Fatalf("machine missing: %v", err)
	}
	if m.Revoked {
		t.Fatal("re-enrollment left the machine revoked")
	}
	if m.PubKey != newPub {
		t.Fatalf("machine still holds the old key: %q", m.PubKey)
	}
	if byOld, _ := st.MachineByPubKey(oldPub); byOld != nil {
		t.Fatal("the revoked key still resolves to a machine")
	}
}

// A revoked machine's agent cannot reconnect on the old key — it must re-enroll —
// but once it has, the new key connects normally. This is the property the whole
// change exists to deliver, asserted at the socket rather than at the store.
func TestRevivedMachineCanConnectAgain(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-web"
	oldPub, oldPriv := newKeyHex(t)
	if err := st.CreateMachine(mach, oldPub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.RevokeMachine(mach); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The revoked agent is refused with the terminal answer, so it retires rather
	// than hammering the control plane — and it is refused only after proving it
	// holds the machine's key, which is what keeps the same answer out of reach
	// of anyone probing for a name (see TestAgentDialCannotEnumerateNames).
	ws, hr := dialAgentHello(t, srv.URL, mach, oldPub, oldPriv)
	if hr.OK || hr.Error != "revoked" {
		t.Fatalf("revoked agent got ok=%v error=%q, want the revoked refusal", hr.OK, hr.Error)
	}
	ws.Close()

	// Re-enroll, and the new key connects.
	newPub, newPriv := newKeyHex(t)
	key := adminKey(t, s, "enroll")
	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "", enrollBody(key, newPub, mach))
	if code != http.StatusOK {
		t.Fatalf("re-enrollment returned %d (%s)", code, body)
	}
	conn := dialAgent(t, srv.URL, mach, newPub, newPriv)
	if got := framesWithin(readAgentFrames(conn), 2*time.Second); len(got) == 0 {
		t.Fatal("the revived agent received nothing after a successful hello")
	}
	if ac := s.br.WaitOnline(mach, 3*time.Second); ac == nil {
		t.Fatal("the revived machine never came online")
	}
}

// The agent socket must not be an oracle. The name arrives in the query string
// from an unauthenticated caller, and the handler used to resolve it *before*
// the hello — so a known name was sent a challenge, an unknown one got silence,
// and a revoked one got an explicit frame, all before any authentication. A
// trivial WebSocket client could enumerate a fleet's org-prefixed hostnames
// that way, which is the reconnaissance a targeted attacker most wants, and the
// route had no rate limit either. The comment in the handler claimed the
// opposite of what the code did.
//
// All three names now get the same thing: a challenge, and then nothing.
func TestAgentDialCannotEnumerateNames(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	knownPub, _ := newKeyHex(t)
	if err := st.CreateMachine("bcross-live", knownPub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed known machine: %v", err)
	}
	revokedPub, _ := newKeyHex(t)
	if err := st.CreateMachine("bcross-revoked", revokedPub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed revoked machine: %v", err)
	}
	if err := st.RevokeMachine("bcross-revoked"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// Probe each name the way an enumerator does: connect, and see what comes
	// back before proving anything. An honest client — a real agent — is the
	// only party that can tell these apart, and it does it by signing.
	seen := map[string]string{}
	for _, name := range []string{"bcross-live", "bcross-revoked", "bcross-does-not-exist"} {
		u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/agent/ws?name=" + name
		ws, _, err := websocket.DefaultDialer.Dial(u, nil)
		if err != nil {
			t.Fatalf("dial %s: %v", name, err)
		}
		var env protocol.Envelope
		_ = ws.SetReadDeadline(time.Now().Add(3 * time.Second))
		if err := ws.ReadJSON(&env); err != nil {
			t.Fatalf("read first frame for %s: %v", name, err)
		}
		// The challenge is the whole of what an unauthenticated caller sees. It
		// must not carry a name, a version, or anything else that varies.
		if env.Type != "hello" {
			t.Fatalf("%s got %q as the first frame, want hello for every name", name, env.Type)
		}
		if env.Payload != nil {
			t.Fatalf("%s got a payload on the challenge frame: %s", name, env.Payload)
		}
		seen[name] = env.Type
		// Silence after that: no hello_result, no revoked frame, no error. The
		// connection does not answer a client that has not authenticated.
		var after protocol.Envelope
		if err := ws.ReadJSON(&after); err == nil {
			t.Fatalf("%s got a second frame %q before authenticating", name, after.Type)
		}
		ws.Close()
	}
	for name, typ := range seen {
		if typ != "hello" {
			t.Fatalf("%s = %q, want an identical challenge", name, typ)
		}
	}
}

// An agent that never authenticates spends its source's budget, and a burst of
// it is refused. A real agent is not counted, which is what keeps a fleet behind
// one address unaffected.
func TestAgentDialIsRateLimitedPerSource(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	knownPub, knownPriv := newKeyHex(t)
	if err := st.CreateMachine("bcross-live", knownPub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// Successes are free: a real agent connects as often as it likes, which is
	// what keeps a fleet behind one address unaffected by its neighbours.
	for i := 0; i < maxAgentDialFailures+10; i++ {
		ws, hr := dialAgentHello(t, srv.URL, "bcross-live", knownPub, knownPriv)
		if !hr.OK {
			t.Fatalf("authenticated dial %d was refused: %q", i, hr.Error)
		}
		ws.Close()
	}
	// Failures are not: the burst is refused once the budget is spent, and the
	// refusal is a status rather than a silent close — it says nothing about the
	// name that was asked for, only about the source.
	agentWS := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/agent/ws?name=bcross-nope"
	var refusal *http.Response
	for i := 0; i < 4*maxAgentDialFailures; i++ {
		ws, resp, err := websocket.DefaultDialer.Dial(agentWS, nil)
		if err != nil {
			refusal = resp
			break
		}
		ws.Close()
	}
	if refusal == nil {
		t.Fatal("a burst of unauthenticated dials was never refused")
	}
	if refusal.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("over-limit dial returned %s, want 429", refusal.Status)
	}
}

// The anti-displacement rule. An active machine's name and key are its own; an
// enrollment must not be able to take either.
func TestReEnrollmentDoesNotDisplaceAnActiveMachine(t *testing.T) {
	s, st := newAuthTestServer(t)
	livePub, _ := newKeyHex(t)
	if err := st.CreateMachine("bcross-web", livePub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key := adminKey(t, s, "enroll")

	// A different key claiming the same name.
	otherPub, _ := newKeyHex(t)
	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "", enrollBody(key, otherPub, "bcross-web"))
	if code != http.StatusConflict {
		t.Fatalf("an active machine's name was taken: %d (%s)", code, body)
	}
	// The live machine is untouched.
	m, _ := st.MachineByName("bcross-web")
	if m == nil || m.PubKey != livePub {
		t.Fatalf("the active machine's key changed: %+v", m)
	}
	if byOther, _ := st.MachineByPubKey(otherPub); byOther != nil {
		t.Fatal("the new key was attached to an active machine")
	}

	// The same key, re-enrolled under its own name, is still a conflict: an
	// active enrollment is not revived, it is reported as already enrolled.
	code, body = bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "", enrollBody(key, livePub, "bcross-web"))
	if code != http.StatusConflict {
		t.Fatalf("an already-enrolled key returned %d, want 409 (%s)", code, body)
	}
	if !strings.Contains(body, "already enrolled") {
		t.Fatalf("refusal does not explain itself: %s", body)
	}
}

// A revoked machine may only come back under its own name: reviving a different
// row with its key would violate the unique key constraint, so the operator is
// told which machine the key belongs to rather than shown a driver error.
func TestReEnrollmentUnderAnotherNameIsRefused(t *testing.T) {
	s, st := newAuthTestServer(t)
	pub, _ := newKeyHex(t)
	if err := st.CreateMachine("bcross-web", pub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.RevokeMachine("bcross-web"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	key := adminKey(t, s, "enroll")

	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "", enrollBody(key, pub, "bcross-other"))
	if code != http.StatusConflict {
		t.Fatalf("revoked key enrolled under another name: %d (%s)", code, body)
	}
	if !strings.Contains(body, "bcross-web") {
		t.Fatalf("refusal does not name the machine the key belongs to: %s", body)
	}
	// Nothing was created for the other name.
	if m, _ := st.MachineByName("bcross-other"); m != nil {
		t.Fatal("a machine was created for the refused name")
	}
}

// The QR path is the other operator-gated way back in, so a revoked key must be
// able to start a pairing. It used to be refused outright, which made revoke a
// one-way door for anyone without an enroll key.
func TestRevokedKeyCanStartAPairing(t *testing.T) {
	s, st := newAuthTestServer(t)
	pub, _ := newKeyHex(t)
	if err := st.CreateMachine("bcross-web", pub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.RevokeMachine("bcross-web"); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/pair/start", "",
		fmt.Sprintf(`{"pub_key":%q,"hostname":"h"}`, pub))
	if code != http.StatusOK {
		t.Fatalf("a revoked key could not start a pairing: %d (%s)", code, body)
	}
	// The challenge code still goes only to the agent's console, and the name is
	// still not echoed back: this endpoint is unauthenticated.
	if strings.Contains(body, "bcross-web") {
		t.Fatalf("pair start leaked the machine name: %s", body)
	}

	// An ACTIVELY enrolled key is still refused, so the pairing path cannot be
	// used to displace a working agent either.
	activePub, _ := newKeyHex(t)
	if err := st.CreateMachine("bcross-live", activePub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	code, _ = bearerJSON(t, s.Routes(), "POST", "/v1/pair/start", "",
		fmt.Sprintf(`{"pub_key":%q,"hostname":"h"}`, activePub))
	if code != http.StatusConflict {
		t.Fatalf("an actively enrolled key started a pairing: %d", code)
	}
}

// ---- temporary enrollments ----

func enrollTemporaryBody(key, pubHex, name string, temporary bool) string {
	return fmt.Sprintf(`{"api_key":%q,"pub_key":%q,"name":%q,"temporary":%t}`, key, pubHex, name, temporary)
}

// A temporary enrollment is recorded as such, and reported to clients — an
// operator has to be able to tell a throwaway row from a machine.
func TestTemporaryEnrollmentIsRecordedAndReported(t *testing.T) {
	s, st := newAuthTestServer(t)
	key := adminKey(t, s, "enroll")
	pub, _ := newKeyHex(t)

	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "",
		enrollTemporaryBody(key, pub, "bcross-tmp", true))
	if code != http.StatusOK {
		t.Fatalf("temporary enrollment returned %d (%s)", code, body)
	}
	m, err := st.MachineByName("bcross-tmp")
	if err != nil || m == nil {
		t.Fatalf("machine missing: %v", err)
	}
	if !m.Temporary || m.Revoked {
		t.Fatalf("expected an active temporary enrollment: %+v", m)
	}

	// And the fleet listing says so, so the web UI can badge it.
	read := adminKey(t, s, "readonly")
	code, listing := bearerJSON(t, s.Routes(), "GET", "/v1/machines", read, "")
	if code != http.StatusOK {
		t.Fatalf("machines: %d %s", code, listing)
	}
	if !strings.Contains(listing, `"temporary":true`) {
		t.Fatalf("the temporary flag is not reported: %s", listing)
	}
}

// The "recorded as permanent" half: enrolling the same machine permanently
// clears the flag, and the machine is then protected like any other live one.
func TestPermanentReEnrollmentClearsTemporaryOverHTTP(t *testing.T) {
	s, st := newAuthTestServer(t)
	key := adminKey(t, s, "enroll")
	pub1, _ := newKeyHex(t)

	if code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "",
		enrollTemporaryBody(key, pub1, "bcross-here", true)); code != http.StatusOK {
		t.Fatalf("temporary enrollment: %d (%s)", code, body)
	}
	// `mach install` on a host that ran plain `mach`: same name, permanent.
	pub2, _ := newKeyHex(t)
	if code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "",
		enrollTemporaryBody(key, pub2, "bcross-here", false)); code != http.StatusOK {
		t.Fatalf("permanent re-enrollment: %d (%s)", code, body)
	}
	m, _ := st.MachineByName("bcross-here")
	if m == nil || m.Temporary {
		t.Fatalf("the temporary flag survived a permanent enrollment: %+v", m)
	}
	if m.PubKey != pub2 {
		t.Fatalf("the permanent enrollment did not re-key the machine: %q", m.PubKey)
	}

	// Now it behaves like any other live machine: a temporary session cannot take
	// it over.
	pub3, _ := newKeyHex(t)
	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "",
		enrollTemporaryBody(key, pub3, "bcross-here", true))
	if code != http.StatusConflict {
		t.Fatalf("a machine made permanent was taken over by a temporary session: %d (%s)", code, body)
	}
}

// A session that was killed before it could retire itself leaves a temporary
// record, and the next run takes it over with no operator action. This is the
// case the temporary marking exists for.
func TestTemporarySessionThatNeverRetiredCanReEnroll(t *testing.T) {
	s, st := newAuthTestServer(t)
	key := adminKey(t, s, "enroll")

	// First run: enrolled temporary, then killed (no retire, no revoke).
	pub1, _ := newKeyHex(t)
	if code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "",
		enrollTemporaryBody(key, pub1, "bcross-tmp", true)); code != http.StatusOK {
		t.Fatalf("first enrollment: %d (%s)", code, body)
	}
	// No revoke, no delete — nothing. Just run it again.
	pub2, _ := newKeyHex(t)
	code, body := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "",
		enrollTemporaryBody(key, pub2, "bcross-tmp", true))
	if code != http.StatusOK {
		t.Fatalf("a temporary session could not retake its own name: %d (%s)", code, body)
	}
	m, _ := st.MachineByName("bcross-tmp")
	if m == nil || m.PubKey != pub2 || !m.Temporary {
		t.Fatalf("the second run did not take over the record: %+v", m)
	}
}

// A temporary session retires its own enrollment on the way out, so a clean exit
// leaves the machine revoked rather than looking like a machine that stopped
// working.
func TestTemporaryAgentRetiresItself(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-tmp"
	pub, priv := newKeyHex(t)
	if err := st.CreateMachine(mach, pub, "h", "linux", "amd64", "v", "", true); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ws := dialAgent(t, srv.URL, mach, pub, priv)

	if err := ws.WriteJSON(protocol.Envelope{Type: "retire"}); err != nil {
		t.Fatalf("write retire: %v", err)
	}
	// The control plane revokes the machine and closes the connection, so the
	// agent's exit is a retirement rather than a disconnect it would retry.
	ws.SetReadDeadline(time.Now().Add(3 * time.Second))
	for {
		var env protocol.Envelope
		if err := ws.ReadJSON(&env); err != nil {
			break // closed, as expected
		}
		if env.Type == "revoked" {
			break
		}
	}
	if m, _ := st.MachineByName(mach); m == nil || !m.Revoked {
		t.Fatalf("a temporary session did not retire its enrollment: %+v", m)
	}
	// Still temporary: the next run can take it straight back over, which is what
	// the operator does after a Ctrl-C.
	if m, _ := st.MachineByName(mach); !m.Temporary {
		t.Fatal("self-retire cleared the temporary flag")
	}
}

// The capability is exactly as narrow as the feature: a PERMANENT agent must not
// be able to retire a machine the operator expects to stay.
func TestPermanentAgentCannotRetireItself(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	mach := "bcross-fixed"
	pub, priv := newKeyHex(t)
	if err := st.CreateMachine(mach, pub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	ws := dialAgent(t, srv.URL, mach, pub, priv)

	if err := ws.WriteJSON(protocol.Envelope{Type: "retire"}); err != nil {
		t.Fatalf("write retire: %v", err)
	}
	// Give the control plane a moment to have (wrongly) acted on it: the
	// connection must also stay up, since nothing should have happened at all.
	time.Sleep(300 * time.Millisecond)
	if m, _ := st.MachineByName(mach); m == nil || m.Revoked {
		t.Fatalf("a permanent agent retired itself: %+v", m)
	}
	if ac := s.br.Get(mach); ac == nil {
		t.Fatal("the permanent agent's connection was closed by its own retire request")
	}
}
