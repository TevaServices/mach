package server

// The exit status of a sealed command is the one fact about it the control plane
// is documented to learn (see SECURITY-NOTES.md: "the audit row records
// `[E2E sealed command]`" — command and output opaque, exit status not), and it
// is what its audit row carries.
//
// It is not in the ciphertext, so it has to ride beside it. It did not: the
// relay read the exit code out of the (empty) plaintext result that shares the
// reply path, which meant every sealed command was audited as exit 0 — a
// machine-refused command that never ran was recorded as having succeeded. The
// e2e suite asserted the placeholder text and never the number, which is how it
// survived. These tests pin the number, in both directions: a reported status is
// recorded, and an unreported one is recorded as absent rather than as 0.

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
	"github.com/TevaServices/mach/internal/store"
	"github.com/gorilla/websocket"
)

// sealedHarness is a machine that answers a sealed dispatch the way a real agent
// does: a ciphertext blob with the exit status in the clear beside it.
type sealedHarness struct {
	s     *Server
	st    *store.Store
	mach  string
	agent *websocket.Conn
}

func newSealedHarness(t *testing.T) *sealedHarness {
	t.Helper()
	h := &sealedHarness{s: nil, st: nil, mach: "bcross-sealed"}
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	h.s, h.st = s, st

	pubHex, priv := seedMachine(t, st, h.mach)
	h.agent = dialAgent(t, srv.URL, h.mach, pubHex, priv)
	return h
}

// replySealed reads the next dispatch and answers it with the given exit status,
// sealed the way an agent does. A nil exit means "the agent did not report one",
// which is what an agent older than the field sends.
func (h *sealedHarness) replySealed(t *testing.T, exit *int) {
	t.Helper()
	// The control plane mirrors the fleet rules at connect, so the first frames
	// on a fresh agent socket are that synchronization, not the dispatch. Skip
	// them: this test is about what a command's reply does.
	var env protocol.Envelope
	for {
		if err := h.agent.ReadJSON(&env); err != nil {
			t.Fatalf("read dispatch: %v", err)
		}
		if env.Type == "exec" {
			break
		}
	}
	var cmd protocol.SealedExecCommand
	if err := json.Unmarshal(env.Payload, &cmd); err != nil {
		t.Fatalf("dispatch payload: %v", err)
	}
	if cmd.SealedB64 == "" {
		t.Fatalf("dispatch was not sealed: %s", env.Payload)
	}
	payload, _ := json.Marshal(protocol.SealedExecResult{SealedB64: "b3BhcXVl", ExitCode: exit})
	if err := h.agent.WriteJSON(protocol.Envelope{Type: "exec_result", ReqID: env.ReqID, Payload: payload}); err != nil {
		t.Fatalf("write sealed result: %v", err)
	}
}

// run sends one sealed exec request and answers it, the way the relay and a
// real agent interleave. The request goes out on its own goroutine because the
// reply has to be produced while it is in flight — and the *testing.T failures
// stay on the test goroutine, since a T may only be failed from there.
func (h *sealedHarness) run(t *testing.T, key string, exit *int) (int, string) {
	t.Helper()
	type result struct {
		code int
		body string
	}
	ch := make(chan result, 1)
	go func() {
		code, body := execReq(t, h.s, key, `{"machine":"`+h.mach+`","sealed":"b3BhcXVl","e2e_pub":"ab"}`)
		ch <- result{code, body}
	}()
	h.replySealed(t, exit)
	r := <-ch
	return r.code, r.body
}

// A sealed command that exits 42 is recorded as 42. Before the fix this row said
// 0 — the exit code of a result struct nobody had filled in.
func TestSealedExecAuditsTheReportedExitStatus(t *testing.T) {
	h := newSealedHarness(t)
	key := adminKey(t, h.s, "exec:*")

	code, body := h.run(t, key, ptr(42))
	if code != http.StatusOK {
		t.Fatalf("sealed exec returned %d, want 200 (%s)", code, body)
	}
	// The wire response carries it too, so a client that reads the field is not
	// handed a 0 standing in for the real status.
	var wire struct {
		ExitCode *int `json:"exit_code"`
	}
	if err := json.Unmarshal([]byte(body), &wire); err != nil {
		t.Fatalf("response is not JSON: %v (%s)", err, body)
	}
	if wire.ExitCode == nil || *wire.ExitCode != 42 {
		t.Fatalf("sealed reply reports exit %v, want 42 (%s)", wire.ExitCode, body)
	}

	entries, err := h.st.AuditList(h.mach, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("sealed exec left %d audit rows, want 1", len(entries))
	}
	e := entries[0]
	if !e.ExitCode.Valid || e.ExitCode.Int64 != 42 {
		t.Fatalf("sealed command audited as %+v, want exit 42", e.ExitCode)
	}
	// Still opaque: the exit status is metadata, the command is not.
	if e.Command != auditSealedLabel {
		t.Fatalf("audit command = %q, want the sealed placeholder", e.Command)
	}
	if e.StdoutSnip != "" || e.StderrSnip != "" {
		t.Fatalf("sealed audit row carries output: %+v", e)
	}
}

// A reported 0 is a real status and must not be confused with "not reported".
func TestSealedExecAuditsAReportedZero(t *testing.T) {
	h := newSealedHarness(t)
	key := adminKey(t, h.s, "exec:*")
	if code, body := h.run(t, key, ptr(0)); code != http.StatusOK {
		t.Fatalf("sealed exec returned %d, want 200 (%s)", code, body)
	}
	entries, err := h.st.AuditList(h.mach, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 || !entries[0].ExitCode.Valid || entries[0].ExitCode.Int64 != 0 {
		t.Fatalf("a reported exit 0 was not recorded as 0: %+v", entries)
	}
}

// An agent that reports no exit status (one older than the field) gets no
// invented one: the row has no exit code rather than a 0 that reads as success.
func TestSealedExecWithoutAReportedStatusAuditsNone(t *testing.T) {
	h := newSealedHarness(t)
	key := adminKey(t, h.s, "exec:*")
	if code, body := h.run(t, key, nil); code != http.StatusOK {
		t.Fatalf("sealed exec returned %d, want 200 (%s)", code, body)
	}
	entries, err := h.st.AuditList(h.mach, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("sealed exec left %d audit rows, want 1", len(entries))
	}
	if entries[0].ExitCode.Valid {
		t.Fatalf("an unreported exit status was recorded as %d", entries[0].ExitCode.Int64)
	}
}

func ptr(n int) *int { return &n }

// A sealed request has no plaintext, so every audit row it produces says so —
// on the refusal paths as well as the reply path. It did not: the display form
// was derived from `command`/`argv` whatever else the request carried, so a
// sealed command refused for a blocked machine was audited with an *empty*
// command — a row that tells the operator nothing — and a caller who attached
// text to a sealed request chose the wording of a row describing a command the
// control plane cannot read.
func TestSealedRefusalAuditsThePlaceholder(t *testing.T) {
	h := newSealedHarness(t)
	key := adminKey(t, h.s, "exec:*")
	if _, err := h.st.SetMachineBlocked(h.mach, true); err != nil {
		t.Fatalf("block machine: %v", err)
	}

	code, body := execReq(t, h.s, key, `{"machine":"`+h.mach+`","sealed":"b3BhcXVl","e2e_pub":"ab"}`)
	if code != http.StatusForbidden {
		t.Fatalf("sealed exec to a blocked machine returned %d, want 403 (%s)", code, body)
	}
	entries, err := h.st.AuditList(h.mach, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("sealed refusal left %d audit rows, want 1", len(entries))
	}
	if entries[0].Command != auditSealedLabel {
		t.Fatalf("sealed refusal audited as %q, want the sealed placeholder", entries[0].Command)
	}
}

// Sealed and plaintext are two ways to say the same thing; a request carrying
// both is refused rather than resolved, so a caller cannot pick the text of an
// audit row for a command the control plane cannot read. Nothing is dispatched
// and nothing is audited — the request never got past validation.
func TestSealedWithPlaintextIsRefused(t *testing.T) {
	h := newSealedHarness(t)
	key := adminKey(t, h.s, "exec:*")

	for _, body := range []string{
		`{"machine":"` + h.mach + `","sealed":"b3BhcXVl","e2e_pub":"ab","command":"rm -rf /"}`,
		`{"machine":"` + h.mach + `","sealed":"b3BhcXVl","e2e_pub":"ab","argv":["rm","-rf","/"]}`,
	} {
		code, resp := execReq(t, h.s, key, body)
		if code != http.StatusBadRequest {
			t.Fatalf("sealed + plaintext returned %d, want 400 (%s)", code, resp)
		}
	}
	entries, err := h.st.AuditList(h.mach, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("a refused request shape left %d audit rows: %+v", len(entries), entries)
	}
	// The machine is still online and nothing was dispatched to it.
	var env protocol.Envelope
	_ = h.agent.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	for h.agent.ReadJSON(&env) == nil {
		if env.Type == "exec" {
			t.Fatal("a refused request shape was dispatched")
		}
	}
}
