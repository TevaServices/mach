package server

// The browser-side pairing flow, driven over HTTP exactly as a phone would.
//
// This is the seam that hid a real bug: the pair page normalized the submitted
// code before comparing it, while the code had been hashed in its dashed display
// form — so every correct approval was refused, and the QR enrollment path could
// never be completed. The store's tests approved with the raw code, the server
// tests exercised normalizeCode alone, and the e2e asserted only that a correct
// code is *refused* after five wrong attempts — which passed precisely because
// the correct code was refused too.
//
// So this test does the whole loop: pair/start → approve → the pairing is really
// approved.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/TevaServices/mach/internal/protocol"
)

func TestPairApprovalWorksOverHTTP(t *testing.T) {
	s, st := newAuthTestServer(t)
	h := s.Routes()

	// The agent asks to pair.
	code, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
		`{"pub_key":"`+strings.Repeat("ab", 32)+`","hostname":"h","os":"linux","arch":"amd64"}`)
	if code != http.StatusOK {
		t.Fatalf("pair start: %d (%s)", code, body)
	}
	var start protocol.PairStartResponse
	if err := json.Unmarshal([]byte(body), &start); err != nil {
		t.Fatalf("decode pair start: %v", err)
	}
	if start.Token == "" || start.Code == "" {
		t.Fatalf("pair start returned no token/code: %s", body)
	}
	// The code goes to the agent's console only, and is displayed dashed.
	if !strings.Contains(start.Code, "-") {
		t.Fatalf("challenge code %q is not the dashed display form", start.Code)
	}

	// The operator opens the pair page — never seeing the code — and types it.
	form := url.Values{
		"code":    {start.Code},
		"org":     {"bcross"},
		"name":    {"web-01"}, // machine part; the page composes <org>-<part>
		"approve": {"1"},
	}
	req := httptest.NewRequest("POST", "/pair/"+start.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d", rec.Code)
	}
	rendered := rec.Body.String()
	if strings.Contains(rendered, "Wrong code") {
		t.Fatal("the correct challenge code was refused by the pair page")
	}
	if strings.Contains(rendered, "Too many wrong") {
		t.Fatal("the correct code counted as a wrong attempt")
	}

	// And the pairing really is approved, with the composed name.
	p, err := st.PairingByToken(start.Token)
	if err != nil || p == nil {
		t.Fatalf("pairing missing: %v", err)
	}
	if got := st.PairingState(p); got != "approved" {
		t.Fatalf("pairing state = %q, want approved", got)
	}
	if p.Name != "bcross-web-01" {
		t.Fatalf("pairing name = %q, want bcross-web-01", p.Name)
	}

	// The agent completes it, and the machine exists.
	claim := fmt.Sprintf(`{"pub_key":%q,"token":%q,"name":%q}`,
		strings.Repeat("ab", 32), start.Token, "bcross-web-01")
	if code, body := bearerJSON(t, h, "POST", "/v1/pair/claim", "", claim); code != http.StatusOK {
		t.Fatalf("claim: %d (%s)", code, body)
	}
	if m, _ := st.MachineByName("bcross-web-01"); m == nil {
		t.Fatal("the claimed machine was not created")
	}
}

// A wrong code must still be refused — the fix for the above must not have
// turned the comparison into one that accepts anything.
func TestPairApprovalRefusesAWrongCodeOverHTTP(t *testing.T) {
	s, st := newAuthTestServer(t)
	h := s.Routes()

	code, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
		`{"pub_key":"`+strings.Repeat("cd", 32)+`","hostname":"h"}`)
	if code != http.StatusOK {
		t.Fatalf("pair start: %d (%s)", code, body)
	}
	var start protocol.PairStartResponse
	_ = json.Unmarshal([]byte(body), &start)

	form := url.Values{"code": {"AAAA-AAAA-AAAA"}, "org": {"bcross"}, "name": {"web-01"}, "approve": {"1"}}
	req := httptest.NewRequest("POST", "/pair/"+start.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if !strings.Contains(rec.Body.String(), "Wrong code") {
		t.Fatal("a wrong challenge code was accepted")
	}
	p, _ := st.PairingByToken(start.Token)
	if p == nil || s.st.PairingState(p) == "approved" {
		t.Fatal("a wrong code approved the pairing")
	}
}

// The pair page must not answer questions about the fleet before the code does.
//
// "Machine name already taken" was checked first, and a name probe cost no code
// attempt — so anyone who started their own pairing (5 per IP per 10 minutes)
// could submit hundreds of names per window and learn which exist, and which are
// revoked or temporary. The org list is printed to anonymous visitors on the
// enrollment page, so the keyspace came with it. The code is what approval is
// gated on; it has to gate the fleet's answers too.
func TestPairPageDoesNotLeakNamesToAWrongCode(t *testing.T) {
	s, st := newAuthTestServer(t)
	h := s.Routes()

	// One name that exists and is active, one that does not. The pair page must
	// not tell them apart to a caller who cannot read the agent's console.
	livePub, _ := newKeyHex(t)
	if err := st.CreateMachine("bcross-live", livePub, "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	post := func(t *testing.T, token string, form url.Values) string {
		t.Helper()
		req := httptest.NewRequest("POST", "/pair/"+token, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("pair post: %d", rec.Code)
		}
		return rec.Body.String()
	}

	for _, name := range []string{"bcross-live", "bcross-free"} {
		probePub, _ := newKeyHex(t)
		code, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
			`{"pub_key":"`+probePub+`","hostname":"h"}`)
		if code != http.StatusOK {
			t.Fatalf("pair start: %d (%s)", code, body)
		}
		var start protocol.PairStartResponse
		_ = json.Unmarshal([]byte(body), &start)

		org, part, _ := strings.Cut(name, "-")
		page := post(t, start.Token, url.Values{
			"code": {"AAAA-AAAA-AAAA"}, "org": {org}, "name": {part}, "approve": {"1"}})
		if strings.Contains(page, "already taken") {
			t.Fatalf("%s: the page answered a fleet question before checking the code", name)
		}
		if !strings.Contains(page, "Wrong code") {
			t.Fatalf("%s: a wrong code was not refused: %s", name, page)
		}
		if p, _ := st.PairingByToken(start.Token); p == nil || s.st.PairingState(p) == "approved" {
			t.Fatalf("%s: a wrong code approved the pairing", name)
		}
	}

	// The name check still happens — it just happens after the code now. A
	// correct code on a taken name is refused exactly as it always was.
	takenPub, _ := newKeyHex(t)
	page, state := approvePair(t, s, takenPub, "bcross-live")
	if !strings.Contains(page, "already taken") {
		t.Fatalf("a taken name was accepted after a correct code: %s", page)
	}
	if state == "approved" {
		t.Fatal("a taken name approved the pairing")
	}
}

// approvePair drives the pair page for a machine name and returns the rendered
// page plus the pairing's resulting state.
func approvePair(t *testing.T, s *Server, pubHex, name string) (page, state string) {
	t.Helper()
	h := s.Routes()
	code, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
		`{"pub_key":"`+pubHex+`","hostname":"h"}`)
	if code != http.StatusOK {
		t.Fatalf("pair start: %d (%s)", code, body)
	}
	var start protocol.PairStartResponse
	if err := json.Unmarshal([]byte(body), &start); err != nil {
		t.Fatalf("decode: %v", err)
	}
	org, part, _ := strings.Cut(name, "-")
	form := url.Values{"code": {start.Code}, "org": {org}, "name": {part}, "approve": {"1"}}
	req := httptest.NewRequest("POST", "/pair/"+start.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("approve: %d", rec.Code)
	}
	p, err := s.st.PairingByToken(start.Token)
	if err != nil || p == nil {
		t.Fatalf("pairing missing: %v", err)
	}
	return rec.Body.String(), s.st.PairingState(p)
}

// The name-taken rule lives in ONE place. It used to be duplicated here with a
// simpler condition — "any row with this name" — which disagreed with the store
// about revoked and temporary rows, so a temporary session could retire itself
// and then never come back under its own name.
func TestPairPageAcceptsANameARevokedOrTemporaryMachineHolds(t *testing.T) {
	for _, tc := range []struct {
		what      string
		revoked   bool
		temporary bool
	}{
		{"revoked", true, false},
		{"temporary", false, true},
		{"revoked and temporary", true, true},
	} {
		t.Run(tc.what, func(t *testing.T) {
			s, st := newAuthTestServer(t)
			if err := st.CreateMachine("bcross-tmp", strings.Repeat("11", 32), "h", "linux", "amd64", "v", "", tc.temporary); err != nil {
				t.Fatalf("seed: %v", err)
			}
			if tc.revoked {
				if err := st.RevokeMachine("bcross-tmp"); err != nil {
					t.Fatalf("revoke: %v", err)
				}
			}
			page, state := approvePair(t, s, strings.Repeat("22", 32), "bcross-tmp")
			if strings.Contains(page, "already taken") {
				t.Fatalf("the pair page refused a %s machine's name: %s", tc.what, page)
			}
			if state != "approved" {
				t.Fatalf("pairing state = %q, want approved", state)
			}
		})
	}
}

// And an ACTIVE, permanent machine's name is still refused — the page must not
// have been loosened into accepting anything.
func TestPairPageStillRefusesAnActiveMachinesName(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-live", strings.Repeat("33", 32), "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	page, _ := approvePair(t, s, strings.Repeat("44", 32), "bcross-live")
	if !strings.Contains(page, "already taken") {
		t.Fatalf("an active machine's name was offered to a new agent: %s", page)
	}
}

// The QR carries a suggestion, and the page opens with it already filled in: the
// org chosen in the dropdown, the machine name in an editable box. That is a
// convenience over the same validation, and the distinction matters — the
// suggestion is agent-reported text (a hostname), so nothing downstream of it
// may be treated as trusted, and the challenge code is not part of it at all.
func TestPairPagePrefillsFromTheQRQuery(t *testing.T) {
	s, _ := newAuthTestServer(t)
	h := s.Routes()

	code, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
		`{"pub_key":"`+strings.Repeat("ab", 32)+`","hostname":"h","os":"linux","arch":"amd64"}`)
	if code != http.StatusOK {
		t.Fatalf("pair start: %d (%s)", code, body)
	}
	var start protocol.PairStartResponse
	if err := json.Unmarshal([]byte(body), &start); err != nil {
		t.Fatalf("decode pair start: %v", err)
	}
	get := func(q string) string {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "/pair/"+start.Token+q, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /pair/...%s: %d", q, rec.Code)
		}
		return rec.Body.String()
	}

	page := get("?org=bcross&name=web-01")
	if !strings.Contains(page, `<option value="bcross" selected>`) {
		t.Errorf("the QR's org is not the selected option:\n%s", page)
	}
	if !strings.Contains(page, `value="web-01"`) {
		t.Errorf("the QR's machine name is not pre-filled:\n%s", page)
	}
	if !strings.Contains(page, "suggested by the") {
		t.Error("the page does not say the pre-filled values came from the enrolling agent")
	}
	// The one thing the QR must never carry. The field is empty on arrival, which
	// is what keeps "a photograph of the QR alone grants nothing" true.
	if strings.Contains(page, `name="code" value=`) || strings.Contains(page, `name="code"value=`) {
		t.Error("the challenge-code field arrives pre-filled")
	}

	// An org this control plane does not have is dropped, not shown: the
	// dropdown cannot offer it, so pre-selecting it would leave the operator
	// looking at a different org than the one they were told, with no sign why.
	if got := get("?org=notconfigured&name=web-01"); strings.Contains(got, "notconfigured") {
		t.Errorf("an unconfigured org reached the page:\n%s", got)
	}
	// A name a machine name may not contain is dropped rather than rewritten or
	// handed to the form to reject — the field starts empty.
	for _, bad := range []string{"Web_01.Example.COM", "web 01", strings.Repeat("x", 49)} {
		if got := get("?name=" + url.QueryEscape(bad)); !strings.Contains(got, `name="name" required value=""`) {
			t.Errorf("name %q was pre-filled:\n%s", bad, got)
		}
	}
}

// A refused approval hands back the org and the name the operator typed, so a
// mistyped challenge code does not also cost them the rest of the form.
func TestPairPageKeepsTypedValuesOnARetry(t *testing.T) {
	s, _ := newAuthTestServer(t)
	h := s.Routes()

	_, body := bearerJSON(t, h, "POST", "/v1/pair/start", "",
		`{"pub_key":"`+strings.Repeat("cd", 32)+`","hostname":"h"}`)
	var start protocol.PairStartResponse
	_ = json.Unmarshal([]byte(body), &start)

	form := url.Values{"code": {"AAAA-AAAA-AAAA"}, "org": {"bcross"}, "name": {"web-01"}, "approve": {"1"}}
	req := httptest.NewRequest("POST", "/pair/"+start.Token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	page := rec.Body.String()
	if !strings.Contains(page, "Wrong code") {
		t.Fatalf("a wrong code was not refused:\n%s", page)
	}
	if !strings.Contains(page, `<option value="bcross" selected>`) || !strings.Contains(page, `value="web-01"`) {
		t.Errorf("the retry form lost what the operator had typed:\n%s", page)
	}
}

// Denying a pairing must render a terminal page. It rendered the approve form
// instead — the state went to "denied" in the store, but the page showed the code
// box and a submit button again, so the operator could not tell the denial had
// taken effect, and the form it was shown posts to a path with no token (which
// does not route). Every other terminal state goes through terminalPair; this
// one now does too.
func TestPairDenyRendersTerminalPage(t *testing.T) {
	s, st := newAuthTestServer(t)
	_, token, code, err := st.CreatePairing("pub", "agent-host", "linux", "amd64", "v", 10*time.Minute)
	if err != nil {
		t.Fatalf("create pairing: %v", err)
	}
	// With the code, because denying is gated on it exactly as approving is —
	// see TestPairDenyWithoutTheCodeIsRefused for why.
	form := url.Values{"deny": {"1"}, "code": {code}}
	req := httptest.NewRequest("POST", "/pair/"+token, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()
	s.Routes().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("deny returned %d", rec.Code)
	}
	body := rec.Body.String()
	// The row really is denied, not merely rendered that way.
	pair, err := st.PairingByToken(token)
	if err != nil || pair == nil {
		t.Fatalf("reload pairing: %v", err)
	}
	if got := st.PairingState(pair); got != "denied" {
		t.Fatalf("pairing state = %q, want denied", got)
	}
	// Terminal: no code field, no submit button.
	if strings.Contains(body, `name="code"`) {
		t.Error("the deny response still renders the code field — the operator is invited to try again")
	}
	if strings.Contains(body, `name="deny"`) {
		t.Error("the deny response still renders the deny button")
	}
	if !strings.Contains(body, "denied") {
		t.Errorf("the deny response does not say the pairing was denied: %s", body)
	}
}

// Denying needs the challenge code too.
//
// It did not, and the page made that hard to see: the deny button sits in the
// same form as the code field, so a browser asked for one — but a direct POST
// did not, and a photographed QR is exactly a direct POST. "A photograph of the
// QR alone still grants nothing" is the property the whole pairing flow exists
// to have, and it was true of approval only: a token holder could terminally
// deny a legitimate enrollment without ever being near the machine.
//
// The other residual powers of a token holder are not closable this way and are
// documented in SECURITY-NOTES instead: five wrong codes burn the pairing, and
// the GET page shows what the machine reported about itself.
func TestPairDenyWithoutTheCodeIsRefused(t *testing.T) {
	s, st := newAuthTestServer(t)
	_, token, code, err := st.CreatePairing("pub", "agent-host", "linux", "amd64", "v", 10*time.Minute)
	if err != nil {
		t.Fatalf("create pairing: %v", err)
	}

	post := func(form url.Values) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "/pair/"+token, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Sec-Fetch-Site", "same-origin")
		rec := httptest.NewRecorder()
		s.Routes().ServeHTTP(rec, req)
		return rec
	}

	// No code at all: refused, and the pairing is still alive.
	if rec := post(url.Values{"deny": {"1"}}); !strings.Contains(rec.Body.String(), "Wrong code") {
		t.Fatalf("a deny with no code was not refused: %s", rec.Body.String())
	}
	// A wrong code: refused too, and counted as the attempt it is.
	if rec := post(url.Values{"deny": {"1"}, "code": {"AAAA-AAAA-AAAA"}}); !strings.Contains(rec.Body.String(), "Wrong code") {
		t.Fatalf("a deny with a wrong code was not refused: %s", rec.Body.String())
	}
	p, _ := st.PairingByToken(token)
	if p == nil || s.st.PairingState(p) != "pending" {
		t.Fatalf("state = %q, want the pairing still pending", s.st.PairingState(p))
	}
	// The right code still denies, so the gate is a gate and not a removal.
	if rec := post(url.Values{"deny": {"1"}, "code": {code}}); !strings.Contains(rec.Body.String(), "denied") {
		t.Fatalf("the right code did not deny: %s", rec.Body.String())
	}
	p, _ = st.PairingByToken(token)
	if p == nil || s.st.PairingState(p) != "denied" {
		t.Fatalf("state = %q, want denied", s.st.PairingState(p))
	}
}
