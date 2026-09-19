package server

// Tests for the two halves of the same bug: a refusal the operator could not see,
// and a confirmation they never received.
//
// Both were invisible in exactly the same way — htmx does not swap non-2xx
// responses and had no error listener, so a refused action did nothing at all;
// and the notice sentences lived only on the ?n= redirect that a scripting-off
// browser follows. With htmx on, which is the normal case, an operator got
// neither an error nor a confirmation. Neither is visible from any assertion
// below the markup, which is why these are structural.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TevaServices/mach/internal/store"
	"github.com/gorilla/websocket"
)

// A refusal is visible to htmx and styled without it, with the status preserved
// in both cases.
func TestUIRefusalIsVisibleToHtmxAndStyledWithoutIt(t *testing.T) {
	s, _, p := newUITestServer(t)
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)

	// A duplicate org is the canonical case: refused with 409, and previously a
	// complete no-op in the browser.
	code, body, rec := uiPOST(t, h, session, csrf, "/ui/orgs/add", "org=bcross", true)
	if code != http.StatusConflict {
		t.Fatalf("duplicate org returned %d, want 409", code)
	}
	// htmx only swaps it because the server names a destination, and app.js only
	// opts in for a response that carries one.
	if got := rec.Header().Get("HX-Retarget"); got != "#ui-error" {
		t.Errorf("HX-Retarget = %q, want #ui-error", got)
	}
	if got := rec.Header().Get("HX-Reswap"); got != "innerHTML" {
		t.Errorf("HX-Reswap = %q, want innerHTML", got)
	}
	if !strings.Contains(body, "already configured") {
		t.Errorf("the refusal does not carry its sentence:\n%s", body)
	}
	// A fragment, not a page: it is swapped into the live region.
	if strings.Contains(body, "<main") {
		t.Error("the htmx refusal is a whole page rather than a fragment")
	}
	if strings.Contains(body, `{"error"`) {
		t.Error("the refusal is still JSON")
	}

	// The same request without htmx: the same status and the same sentence, on a
	// page. This used to be a raw JSON object in the browser window.
	code, body, _ = uiPOST(t, h, session, csrf, "/ui/orgs/add", "org=bcross", false)
	if code != http.StatusConflict {
		t.Fatalf("non-htmx duplicate org returned %d, want 409", code)
	}
	if !strings.Contains(body, "<main id=\"main\">") {
		t.Error("the non-htmx refusal is not a page through the shell")
	}
	if !strings.Contains(body, "already configured") {
		t.Error("the non-htmx refusal lost its sentence")
	}
	if strings.Contains(body, `{"error"`) {
		t.Error("the non-htmx refusal is still JSON in the browser")
	}
}

// A successful action carries its confirmation out of band, so the operator
// learns that what they clicked actually happened.
func TestUIActionNoticeArrivesOutOfBand(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)
	if err := st.CreateMachine("bcross-a", "pub", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	code, body, _ := uiPOST(t, h, session, csrf, "/ui/block", "machine=bcross-a", true)
	if code != http.StatusOK {
		t.Fatalf("block returned %d", code)
	}
	if !strings.Contains(body, `hx-swap-oob="innerHTML:#ui-notice"`) {
		t.Errorf("the response carries no out-of-band notice:\n%s", body)
	}
	// The sentence comes from uiNotices, so the htmx and no-JS paths cannot drift.
	if !strings.Contains(body, uiNotices["blocked"]) {
		t.Error("the out-of-band notice does not carry the blocked sentence")
	}
	// innerHTML rather than outerHTML: the live region has to persist across the
	// change for the change to be announced.
	if strings.Contains(body, `hx-swap-oob="outerHTML:#ui-notice"`) {
		t.Error("the notice replaces its live region instead of filling it")
	}

	// The polled fragment must not carry it: it is swapped every five seconds, so
	// an out-of-band notice there would re-announce forever.
	poll := uiGetPage(t, h, session, "/ui/machines")
	if strings.Contains(poll, "hx-swap-oob") || strings.Contains(poll, "ui-notice") {
		t.Error("the polled fragment carries the notice, which would repeat every tick")
	}

	// And a plain page load must not carry it either — there is no swap to process
	// it, so it would sit in the document as a stray duplicate of what the shell
	// already rendered.
	page := uiGetPage(t, h, session, "/ui")
	if strings.Contains(page, "hx-swap-oob") {
		t.Error("a full page render carries an out-of-band notice")
	}
}

// With scripting off, Delete asks for confirmation on a page rather than
// stranding the operator on a bare fragment with no navigation.
func TestUIDeleteConfirmWithoutHtmxIsAPage(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)
	if err := st.CreateMachine("bcross-a", "pub", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	// htmx gets the panel as a fragment, to drop into #confirm.
	code, body, _ := uiPOST(t, h, session, csrf, "/ui/delete", "machine=bcross-a", true)
	if code != http.StatusOK {
		t.Fatalf("delete confirmation returned %d", code)
	}
	if strings.Contains(body, "<main") {
		t.Error("the htmx confirmation is a whole page rather than a panel")
	}

	// Without it, the same request is a page: this used to navigate the browser to
	// a shell-less panel with no way back, on the one action that is deliberately
	// hard to reach.
	code, body, _ = uiPOST(t, h, session, csrf, "/ui/delete", "machine=bcross-a", false)
	if code != http.StatusOK {
		t.Fatalf("non-htmx delete confirmation returned %d", code)
	}
	if !strings.Contains(body, `<main id="main">`) {
		t.Error("the non-htmx confirmation is not a page through the shell")
	}
	// The typed-name gate is the part that must not drift between the two paths.
	if !strings.Contains(body, `name="confirm_name"`) {
		t.Error("the page confirmation has no typed-name field")
	}
	if !strings.Contains(body, `name="confirm" value="1"`) {
		t.Error("the page confirmation has no confirm flag")
	}
	// No hx-* attribute at all, and Cancel is a real link — otherwise the page
	// depends on the script it is the fallback for.
	if strings.Contains(body, "hx-post") || strings.Contains(body, "hx-target") {
		t.Error("the page confirmation carries htmx attributes")
	}
	if !strings.Contains(body, `href="/ui">Cancel</a>`) {
		t.Error("the page confirmation has no working Cancel link")
	}
}

// No refusal echoes what was posted at it.
//
// Every refusal sentence in the UI is a fixed literal, and exactly one used to
// interpolate the submitted org — the pinned-org one. The echo was bounded: the
// branch is only reachable for a name orgPinned already recognises, so it could
// only ever repeat a value the page displays anyway. That is why this is a
// consistency fix rather than an injection fix, and the test is written to say
// so: it asserts the sentence is the fixed one and carries no interpolated name,
// on both paths.
func TestUIRefusalsCarryNoEcho(t *testing.T) {
	s, _, p := newUITestServer(t)
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)

	// "bcross" is the primary org. It comes from the environment, which makes it
	// pinned, which is the only way into this branch.
	const pinned = "bcross"
	if !s.orgPinned(pinned) {
		t.Fatalf("%q is not pinned on the test server; this test would prove nothing", pinned)
	}

	const fixed = "That org comes from the environment (MACH_ORG/MACH_ORGS) and cannot be removed from here."

	for _, htmx := range []bool{false, true} {
		code, body, _ := uiPOST(t, h, session, csrf, "/ui/orgs/remove", "org="+pinned, htmx)
		if code != http.StatusConflict {
			t.Fatalf("removing a pinned org (htmx=%v) returned %d, want 409", htmx, code)
		}
		if !strings.Contains(body, "cannot be removed") {
			t.Errorf("htmx=%v: the refusal lost the sentence e2e asserts on", htmx)
		}
		// The fixed sentence names no org at all, so the submitted value cannot
		// appear in the refusal.
		if !strings.Contains(body, fixed) {
			t.Errorf("htmx=%v: the refusal is not the fixed sentence", htmx)
		}
	}

	// An org that is not registered is refused by a fixed sentence too, and a
	// hostile value must not come back in any form.
	payload := `<script>alert(1)</script>`
	code, body, _ := uiPOST(t, h, session, csrf, "/ui/orgs/remove", "org="+payload, false)
	if code != http.StatusNotFound {
		t.Fatalf("removing an unknown org returned %d, want 404", code)
	}
	if strings.Contains(body, payload) || strings.Contains(body, "&lt;script&gt;") {
		t.Error("the refusal echoes the submitted value")
	}
}

// A scope refusal is the audit event a fleet most wants to see — an
// exec-scoped key asking for a machine outside its allowlist is either a
// mistake worth seeing or a stolen key finding out what else it can reach — and
// it was the one refusal on the command paths that left no trace at all. A
// policy refusal for an authorized key was recorded; a key probing machine
// names was not.
//
// The row names the machine that was asked for, which is the fact that makes it
// readable: "which names did this key try" is the question an operator has.
func TestScopeRefusalsAreAudited(t *testing.T) {
	s, st := newAuthTestServer(t)
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)
	if err := st.CreateMachine("bcross-web", "pub-web", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed web: %v", err)
	}
	if err := st.CreateMachine("bcross-db", "pub-db", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed db: %v", err)
	}
	// Scoped to web, probing db.
	key := adminKey(t, s, "exec:bcross-web")

	code, body := execReq(t, s, key, `{"machine":"bcross-db","command":"echo hi"}`)
	if code != http.StatusForbidden {
		t.Fatalf("out-of-scope exec returned %d, want 403 (%s)", code, body)
	}
	assertNotScopedRows(t, st, "bcross-db", 1)

	// The streaming endpoint is command execution, so its scope refusal has to
	// be as visible as the one-shot path's.
	u := "ws" + strings.TrimPrefix(srv.URL, "http") + "/v1/console/stream?machine=bcross-db"
	hd := http.Header{}
	hd.Set("Authorization", "Bearer "+key)
	if ws, resp, err := websocket.DefaultDialer.Dial(u, hd); err == nil {
		ws.Close()
		t.Fatal("an out-of-scope key opened a streaming session")
	} else if resp == nil || resp.StatusCode != http.StatusForbidden {
		t.Fatalf("out-of-scope streaming: resp = %v, want 403", resp)
	}
	assertNotScopedRows(t, st, "bcross-db", 2)

	// Nothing was written against the machine the key *is* allowed to use: the
	// row names what was asked for, not what was permitted.
	if entries, _ := st.AuditList("bcross-web", 10); len(entries) != 0 {
		t.Fatalf("a scope refusal was recorded against the wrong machine: %+v", entries)
	}
	// And the key's own machine still passes the scope gate, so recording the
	// refusal did not quietly become a refusal by accident.
	if !keyCanExecOn("exec:bcross-web", "bcross-web") {
		t.Fatal("the scope rule stopped allowing the key's own machine")
	}
}

// assertNotScopedRows checks every row recorded for a machine is a scope-refusal
// row, and that there are exactly want of them. The marker and the refusal exit
// code are what keep those rows distinguishable from a real command.
func assertNotScopedRows(t *testing.T, st *store.Store, machine string, want int) {
	t.Helper()
	entries, err := st.AuditList(machine, 10)
	if err != nil {
		t.Fatalf("audit list: %v", err)
	}
	if len(entries) != want {
		t.Fatalf("scope refusals for %s left %d audit rows, want %d", machine, len(entries), want)
	}
	for _, e := range entries {
		if e.Command != auditNotScopedLabel {
			t.Fatalf("scope refusal audited as %q, want the not-scoped marker", e.Command)
		}
		if !e.ExitCode.Valid || e.ExitCode.Int64 != execRefused {
			t.Fatalf("scope refusal audited as exit %+v, want %d", e.ExitCode, execRefused)
		}
		if !strings.Contains(e.StderrSnip, "not scoped") {
			t.Fatalf("scope refusal does not say why: %+v", e)
		}
	}
}

// Unrestricted exec is the `exec:*` scope, and admin power comes from it and
// nothing else.
//
// `exec:web|*` mints a key whose allowlist holds a literal `*`. No machine is
// named `*`, so the key could exec on no real machine — while the admin check
// read the entry as "all machines" and handed it block, revoke and delete over
// the whole fleet. A key scoped that way is always a typo for `exec:*`, so the
// mint refuses it now too; this is the check that has to be right even for
// scopes written before that.
func TestAdminPowerComesFromTheUnrestrictedScopeOnly(t *testing.T) {
	for _, scopes := range []string{"exec:*", "readonly,exec:*"} {
		if !adminScopeOK(scopes) {
			t.Errorf("adminScopeOK(%q) = false, want true", scopes)
		}
	}
	for _, scopes := range []string{
		"exec:web|*", // the shape that used to confer admin
		"exec:*|web",
		"exec:web",
		"readonly",
		"enroll",
		"",
	} {
		if adminScopeOK(scopes) {
			t.Errorf("adminScopeOK(%q) = true — an allowlist is not fleet-wide power", scopes)
		}
	}
}

// The register endpoint checks an API key, so it belongs to the same
// auth-failure control every other bearer surface uses. It did not: the
// documented "auth-failure rate limit" simply did not cover it, and a limit an
// operator has to remember the exceptions to is one they cannot rely on. The
// keys are 192-bit so guessing one is not a real attack — the point is that the
// control is where the documentation says it is.
func TestRegisterEndpointCountsFailedKeyAttempts(t *testing.T) {
	s, st := newAuthTestServer(t)
	if err := st.CreateMachine("bcross-web", "pub-web", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	body := `{"api_key":"mach_wrong","pub_key":"` + strings.Repeat("ab", 32) + `","name":"bcross-new"}`
	var refused int
	for i := 0; i < 200; i++ {
		code, resp := bearerJSON(t, s.Routes(), "POST", "/v1/register/apikey", "", body)
		if code == http.StatusTooManyRequests {
			refused++
			_ = resp
			break
		}
		if code != http.StatusForbidden {
			t.Fatalf("attempt %d returned %d (%s), want 403", i, code, resp)
		}
	}
	if refused == 0 {
		t.Fatal("a burst of wrong enroll keys was never throttled")
	}

	// A correct key is still accepted once the burst stops, so the limiter is a
	// limit and not a lockout. (A new server: the failed attempts are keyed to
	// the test's own loopback address and the limiter is in-memory.)
	s2, st2 := newAuthTestServer(t)
	if err := st2.CreateMachine("bcross-web", "pub-web", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}
	key := adminKey(t, s2, "enroll")
	good := `{"api_key":"` + key + `","pub_key":"` + strings.Repeat("cd", 32) + `","name":"bcross-web-2"}`
	if code, resp := bearerJSON(t, s2.Routes(), "POST", "/v1/register/apikey", "", good); code != http.StatusOK {
		t.Fatalf("a correct enroll key returned %d (%s)", code, resp)
	}
}
