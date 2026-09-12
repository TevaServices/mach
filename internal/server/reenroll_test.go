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
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bcross/mach/internal/protocol"
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

// dialAgentExpectRefusal dials the agent endpoint WITHOUT attempting a hello.
//
// A revoked machine is answered before the handshake: the control plane upgrades,
// writes the terminal frame and closes. So the test cannot use dialAgent, which
// would fail on the missing challenge frame — and the refusal is exactly what it
// wants to observe.
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
	oldPub, _ := newKeyHex(t)
	if err := st.CreateMachine(mach, oldPub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.RevokeMachine(mach); err != nil {
		t.Fatalf("revoke: %v", err)
	}

	// The revoked agent is refused with the terminal frame, so it retires rather
	// than hammering the control plane.
	ws := dialAgentExpectRefusal(t, srv.URL, mach)
	var env protocol.Envelope
	if err := ws.ReadJSON(&env); err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	if env.Type != "revoked" {
		t.Fatalf("revoked agent got %q, want revoked", env.Type)
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
