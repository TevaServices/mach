package server

// Tests for the control-plane web UI: that it is absent unless configured, that
// signing in works, and that the CSRF and session layers actually refuse the
// requests they exist to refuse.
//
// The identity provider is a fake implementing oidcauth.Provider, so nothing here
// touches the network. The real verifier — signatures, audience, expiry, nonce —
// is proven separately in internal/oidcauth against a fake *issuer*, which is the
// opposite arrangement and deliberately so: these tests are about the handlers,
// those are about the crypto.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bcross/mach/internal/broker"
	"github.com/bcross/mach/internal/oidcauth"
	"github.com/bcross/mach/internal/store"
)

type fakeProvider struct {
	ident oidcauth.Identity
	err   error

	// lastState and lastNonce record what the handler asked for, so the callback
	// can be driven with the right state without guessing.
	lastState string
	lastNonce string
	calls     int
}

func (f *fakeProvider) AuthCodeURL(state, nonce string) string {
	f.lastState, f.lastNonce = state, nonce
	// The handler must not leak the nonce into the URL it builds; if it did, a
	// provider that logged its requests would hold the anti-replay value.
	return "https://idp.test/authorize?state=" + url.QueryEscape(state)
}

func (f *fakeProvider) Exchange(ctx context.Context, code, nonce string) (oidcauth.Identity, error) {
	f.calls++
	if f.err != nil {
		return oidcauth.Identity{}, f.err
	}
	if nonce != f.lastNonce {
		return oidcauth.Identity{}, fmt.Errorf("nonce mismatch: %q vs %q", nonce, f.lastNonce)
	}
	return f.ident, nil
}

// clearOIDCEnv makes the ambient environment explicit, so a developer with
// MACH_OIDC_* exported cannot silently change what these tests are testing.
func clearOIDCEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{envOIDCIssuer, envOIDCClientID, envOIDCClientSecret, envOIDCRedirectURL, envOIDCScopes, envOIDCDomains} {
		t.Setenv(k, "")
	}
}

func newUITestServer(t *testing.T) (*Server, *store.Store, *fakeProvider) {
	t.Helper()
	clearOIDCEnv(t)
	s, st := newAuthTestServer(t)
	p := &fakeProvider{ident: oidcauth.Identity{Subject: "op-1", Email: "op@example.com", EmailVerified: true}}
	s.EnableUI(p, "http://127.0.0.1:8099/ui/callback", false)
	return s, st, p
}

// uiSignIn drives the whole sign-in flow and returns the session cookie, the CSRF
// token, and the session cookie jar's raw token.
func uiSignIn(t *testing.T, s *Server, p *fakeProvider) (session *http.Cookie, csrf string) {
	t.Helper()
	h := s.Routes()

	// /ui/login → redirect to the provider, plus the state cookie.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/ui/login", nil))
	if rec.Code != http.StatusFound {
		t.Fatalf("login returned %d, want 302 (%s)", rec.Code, rec.Body.String())
	}
	if p.lastState == "" || p.lastNonce == "" {
		t.Fatal("login did not ask the provider for a state and nonce")
	}
	stateCookie := cookieNamed(t, rec, uiStateCookie)
	if stateCookie == nil {
		t.Fatal("login did not set a state cookie")
	}

	// /ui/callback with the matching state cookie.
	req := httptest.NewRequest("GET", "/ui/callback?state="+url.QueryEscape(p.lastState)+"&code=abc", nil)
	req.AddCookie(stateCookie)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("callback returned %d, want 303 (%s)", rec.Code, rec.Body.String())
	}
	session = cookieNamed(t, rec, uiSessionCookie)
	if session == nil {
		t.Fatal("callback did not set a session cookie")
	}
	sess, ok := s.ui.sessions.get(session.Value)
	if !ok {
		t.Fatal("the session cookie does not resolve to a live session")
	}
	return session, sess.CSRF
}

func cookieNamed(t *testing.T, rec *httptest.ResponseRecorder, name string) *http.Cookie {
	t.Helper()
	for _, c := range rec.Result().Cookies() {
		if c.Name == name {
			return c
		}
	}
	return nil
}

// uiPOST posts a form as a signed-in operator would.
func uiPOST(t *testing.T, h http.Handler, session *http.Cookie, csrf, target, form string, htmx bool) (int, string, *httptest.ResponseRecorder) {
	t.Helper()
	req := httptest.NewRequest("POST", target, strings.NewReader(form))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if session != nil {
		req.AddCookie(session)
	}
	if csrf != "" {
		req.Header.Set("X-CSRF-Token", csrf)
	}
	if htmx {
		req.Header.Set("HX-Request", "true")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code, rec.Body.String(), rec
}

// With no OIDC configuration at all there is no /ui surface — not a UI that
// refuses, but no route to probe. This is the fail-closed property.
func TestUIAbsentWhenOIDCUnconfigured(t *testing.T) {
	clearOIDCEnv(t)
	s, _ := newAuthTestServer(t)
	h := s.Routes()
	for _, target := range []string{"/ui", "/ui/", "/ui/login", "/ui/callback", "/ui/machines", "/ui/orgs"} {
		if code, _ := bearerJSON(t, h, "GET", target, "", ""); code != http.StatusNotFound {
			t.Fatalf("%s returned %d with no OIDC configured, want 404", target, code)
		}
	}
	// And the enrollment page still renders: registering the UI must not break
	// the public surface.
	if code, body := bearerJSON(t, h, "GET", "/", "", ""); code != http.StatusOK || !strings.Contains(body, "set up this machine") {
		t.Fatalf("enrollment page broken: %d", code)
	}
}

// A partly configured UI is a startup failure naming the missing variable,
// rather than a control plane that boots with its admin surface silently absent.
func TestUIPartialEnvIsFatal(t *testing.T) {
	clearOIDCEnv(t)
	t.Setenv(envOIDCIssuer, "https://idp.example")
	t.Setenv(envOIDCClientID, "mach-ui")
	// Secret deliberately left unset.

	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	t.Cleanup(func() { st.Close() })

	defer func() {
		r := recover()
		if r == nil {
			t.Fatal("New accepted a partially configured UI; want a refusal")
		}
		if !strings.Contains(fmt.Sprint(r), envOIDCClientSecret) {
			t.Fatalf("refusal does not name the missing variable: %v", r)
		}
	}()
	New(st, broker.New(), "bcross", filepath.Join(t.TempDir(), "key"))
}

// Every UI read requires a session, and sends the visitor to sign in rather than
// rendering anything.
func TestUIRequiresSession(t *testing.T) {
	s, _, _ := newUITestServer(t)
	h := s.Routes()
	req := httptest.NewRequest("GET", "/ui", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther || rec.Header().Get("Location") != "/ui/login" {
		t.Fatalf("GET /ui without a session returned %d -> %q", rec.Code, rec.Header().Get("Location"))
	}
}

// The callback must be bound to the browser that started the login. Without the
// state cookie an attacker can complete a sign-in in someone else's browser.
func TestUICallbackRefusesWrongBrowser(t *testing.T) {
	s, _, p := newUITestServer(t)
	h := s.Routes()

	req := httptest.NewRequest("GET", "/ui/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	state := p.lastState
	if state == "" {
		t.Fatal("no state issued")
	}
	good := cookieNamed(t, rec, uiStateCookie)

	// No state cookie at all.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/ui/callback?state="+url.QueryEscape(state)+"&code=abc", nil))
	if rec.Code == http.StatusSeeOther {
		t.Fatal("callback completed without the state cookie")
	}

	// A different browser's state cookie.
	req = httptest.NewRequest("GET", "/ui/callback?state="+url.QueryEscape(state)+"&code=abc", nil)
	req.AddCookie(&http.Cookie{Name: uiStateCookie, Value: "some-other-binding"})
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code == http.StatusSeeOther {
		t.Fatal("callback completed with a mismatched state cookie")
	}
	if p.calls != 0 {
		t.Fatal("the provider was consulted before the state was validated")
	}

	// The correct cookie still works, so the refusals above are the binding.
	req = httptest.NewRequest("GET", "/ui/callback?state="+url.QueryEscape(state)+"&code=abc", nil)
	req.AddCookie(good)
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("a correct callback was refused: %d", rec.Code)
	}
}

// A state is single-use: replaying a captured callback finds nothing.
func TestUICallbackStateIsSingleUse(t *testing.T) {
	s, _, p := newUITestServer(t)
	h := s.Routes()
	req := httptest.NewRequest("GET", "/ui/login", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	state, good := p.lastState, cookieNamed(t, rec, uiStateCookie)

	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("GET", "/ui/callback?state="+url.QueryEscape(state)+"&code=abc", nil)
		req.AddCookie(good)
		rec = httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if i == 0 && rec.Code != http.StatusSeeOther {
			t.Fatalf("first callback refused: %d", rec.Code)
		}
		if i == 1 && rec.Code == http.StatusSeeOther {
			t.Fatal("a replayed callback was accepted")
		}
	}
}

// The provider's own error text is never rendered.
func TestUICallbackDoesNotEchoProviderText(t *testing.T) {
	s, _, _ := newUITestServer(t)
	h := s.Routes()
	req := httptest.NewRequest("GET", "/ui/callback?error=access_denied&error_description=SECRET-OPERATOR-TEXT", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if strings.Contains(rec.Body.String(), "SECRET-OPERATOR-TEXT") {
		t.Fatal("the provider's error_description was rendered into the page")
	}
}

// A state-changing POST is refused without the synchronizer token, and the
// refusal must leave the machine alone.
func TestUIPostRequiresCSRF(t *testing.T) {
	s, st, p := newUITestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)

	// No token.
	if code, _, _ := uiPOST(t, h, session, "", "/ui/block", "machine=bcross-a", true); code != http.StatusForbidden {
		t.Fatalf("POST without a CSRF token returned %d, want 403", code)
	}
	// A wrong token.
	if code, _, _ := uiPOST(t, h, session, "not-the-token", "/ui/block", "machine=bcross-a", true); code != http.StatusForbidden {
		t.Fatalf("POST with a bad CSRF token returned %d, want 403", code)
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil || m.Blocked {
		t.Fatal("a refused request changed the machine")
	}
	// No session at all.
	if code, _, _ := uiPOST(t, h, nil, csrf, "/ui/block", "machine=bcross-a", true); code == http.StatusOK {
		t.Fatal("POST without a session was accepted")
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil || m.Blocked {
		t.Fatal("a session-less request changed the machine")
	}
}

// A cross-site form post is refused before anything else runs.
func TestUIPostRefusesCrossSite(t *testing.T) {
	s, st, p := newUITestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)

	req := httptest.NewRequest("POST", "/ui/block", strings.NewReader("machine=bcross-a"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("X-CSRF-Token", csrf)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("cross-site POST returned %d, want 403", rec.Code)
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil || m.Blocked {
		t.Fatal("a cross-site request changed the machine")
	}
}

// The CSRF token the operator's browser is given must be the one the server
// expects: a page that rendered a different value would make every button fail.
func TestUIPageCarriesTheSessionCSRF(t *testing.T) {
	s, _, p := newUITestServer(t)
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)

	req := httptest.NewRequest("GET", "/ui", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet page returned %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, csrf) {
		t.Fatal("the page does not carry the session's CSRF token")
	}
	// And it is sent on every htmx request, not only the ones with a hidden field.
	if !strings.Contains(body, "X-CSRF-Token") {
		t.Fatal("the shell does not attach the CSRF token to htmx requests")
	}
}

// Blocking and unblocking through the UI, round trip, with the fragment coming
// back for an htmx request.
func TestUIBlockUnblockRoundTrip(t *testing.T) {
	s, st, p := newUITestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)

	code, body, _ := uiPOST(t, h, session, csrf, "/ui/block", "machine=bcross-a", true)
	if code != http.StatusOK {
		t.Fatalf("block returned %d (%s)", code, body)
	}
	if !strings.Contains(body, "blocked") {
		t.Fatalf("the refreshed table does not show the block: %s", body)
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil || !m.Blocked {
		t.Fatal("block did not take effect")
	}
	// The action is in the audit trail, attributed to the operator's subject.
	entries, err := st.AuditList("bcross-a", 10)
	if err != nil || len(entries) == 0 {
		t.Fatalf("block was not audited: %v %d", err, len(entries))
	}
	if entries[0].Source != "ui:op-1" {
		t.Fatalf("audit source = %q, want ui:op-1", entries[0].Source)
	}

	code, _, _ = uiPOST(t, h, session, csrf, "/ui/unblock", "machine=bcross-a", true)
	if code != http.StatusOK {
		t.Fatalf("unblock returned %d", code)
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil || m.Blocked {
		t.Fatal("unblock did not take effect")
	}
}

// A non-htmx post gets a redirect rather than a bare fragment.
func TestUIPostWithoutHtmxRedirects(t *testing.T) {
	s, st, p := newUITestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)
	code, _, rec := uiPOST(t, h, session, csrf, "/ui/block", "machine=bcross-a", false)
	if code != http.StatusSeeOther {
		t.Fatalf("plain form post returned %d, want 303", code)
	}
	if loc := rec.Header().Get("Location"); !strings.HasPrefix(loc, "/ui?n=") {
		t.Fatalf("redirect to %q, want the fleet page with a notice", loc)
	}
}

// Delete is the sharpest action available and needs the name typed.
func TestUIDeleteRequiresTypedName(t *testing.T) {
	s, st, p := newUITestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)

	// First click: a confirmation fragment, and nothing happens.
	code, body, _ := uiPOST(t, h, session, csrf, "/ui/delete", "machine=bcross-a", true)
	if code != http.StatusOK {
		t.Fatalf("delete confirm returned %d", code)
	}
	if !strings.Contains(body, "confirm_name") {
		t.Fatalf("no typed-name confirmation was rendered: %s", body)
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil {
		t.Fatal("the machine was deleted before confirmation")
	}

	// Confirmed but with the wrong name.
	code, _, _ = uiPOST(t, h, session, csrf, "/ui/delete", "machine=bcross-a&confirm=1&confirm_name=bcross-b", true)
	if code != http.StatusOK {
		t.Fatalf("wrong-name confirm returned %d", code)
	}
	if m, _ := st.MachineByName("bcross-a"); m == nil {
		t.Fatal("a mismatched confirm_name deleted the machine")
	}

	// Confirmed properly.
	code, _, _ = uiPOST(t, h, session, csrf, "/ui/delete", "machine=bcross-a&confirm=1&confirm_name=bcross-a", true)
	if code != http.StatusOK {
		t.Fatalf("confirmed delete returned %d", code)
	}
	if m, _ := st.MachineByName("bcross-a"); m != nil {
		t.Fatal("the machine survived a confirmed delete")
	}
	// And the deletion is attributable: audit rows outlive the machine row.
	entries, err := st.AuditList("bcross-a", 10)
	if err != nil || len(entries) == 0 {
		t.Fatalf("delete was not audited: %v %d", err, len(entries))
	}
	if entries[0].Source != "ui:op-1" || entries[0].Command != "delete machine" {
		t.Fatalf("audit row is not the deletion: %+v", entries[0])
	}
}

// Revoked machines must appear in the UI's fleet list: delete is the only way to
// free a revoked machine's name, so hiding them would make the recovery path
// unreachable from the UI.
func TestUIFleetIncludesRevokedMachines(t *testing.T) {
	s, st, _ := newUITestServer(t)
	if err := st.CreateMachine("bcross-a", "pub-a", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.RevokeMachine("bcross-a"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	rows, err := s.fleetRows()
	if err != nil {
		t.Fatalf("fleetRows: %v", err)
	}
	if len(rows) != 1 || !rows[0].Revoked {
		t.Fatalf("revoked machine missing from the UI list: %+v", rows)
	}
}

// Org management: add, duplicate, and the two refusals (pinned, still in use).
func TestUIOrgLifecycle(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)

	code, body, _ := uiPOST(t, h, session, csrf, "/ui/orgs/add", "org=acme", true)
	if code != http.StatusOK {
		t.Fatalf("add org returned %d (%s)", code, body)
	}
	if exists, err := st.OrgExists("acme"); err != nil || !exists {
		t.Fatalf("org was not stored: %v %v", exists, err)
	}

	// A duplicate is a conflict, not a silent success.
	if code, _, _ := uiPOST(t, h, session, csrf, "/ui/orgs/add", "org=acme", true); code != http.StatusConflict {
		t.Fatalf("duplicate add returned %d, want 409", code)
	}
	// A malformed label is refused before it reaches the store.
	if code, _, _ := uiPOST(t, h, session, csrf, "/ui/orgs/add", "org=a", true); code != http.StatusBadRequest {
		t.Fatalf("one-character org accepted: %d", code)
	}
	if code, _, _ := uiPOST(t, h, session, csrf, "/ui/orgs/add", "org=a_b", true); code != http.StatusBadRequest {
		t.Fatalf("underscore org accepted: %d", code)
	}

	// An org that comes from the environment is pinned and cannot be removed.
	if code, _, _ := uiPOST(t, h, session, csrf, "/ui/orgs/remove", "org=bcross", true); code != http.StatusConflict {
		t.Fatalf("removing a pinned org returned %d, want 409", code)
	}
	if !s.orgRegistered("bcross") {
		t.Fatal("the pinned org was removed")
	}

	// Removal is refused while machines exist under the prefix.
	if err := st.CreateMachine("acme-1", "pub-1", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if code, _, _ := uiPOST(t, h, session, csrf, "/ui/orgs/remove", "org=acme", true); code != http.StatusConflict {
		t.Fatalf("removing an org in use returned %d, want 409", code)
	}
	if exists, _ := st.OrgExists("acme"); !exists {
		t.Fatal("the org was removed while it still had machines")
	}

	// Once the machine is gone, removal succeeds.
	if err := st.DeleteMachine("acme-1"); err != nil {
		t.Fatalf("delete machine: %v", err)
	}
	if code, _, _ := uiPOST(t, h, session, csrf, "/ui/orgs/remove", "org=acme", true); code != http.StatusOK {
		t.Fatalf("removing an unused org returned %d", code)
	}
	if exists, _ := st.OrgExists("acme"); exists {
		t.Fatal("the org survived removal")
	}
}

// Adding an org has to make that prefix enrollable, or the feature does nothing.
// This is the behaviour change: API-key enrollment used to validate against the
// primary org alone while the pair page accepted any configured org.
func TestEnrollmentAcceptsAnyConfiguredOrg(t *testing.T) {
	clearOIDCEnv(t)
	t.Setenv("MACH_ORGS", "")
	s, st := newAuthTestServer(t)
	h := s.Routes()

	key := adminKey(t, s, "enroll")
	pub := strings.Repeat("ab", 32) // 64 hex chars, the shape validPubKey wants
	body := func(name string) string {
		return fmt.Sprintf(`{"api_key":%q,"pub_key":%q,"name":%q}`, key, pub, name)
	}

	// The primary org works, as it always did.
	if code, resp := bearerJSON(t, h, "POST", "/v1/register/apikey", "", body("bcross-a")); code != http.StatusOK {
		t.Fatalf("primary-org enrollment failed: %d (%s)", code, resp)
	}
	// An org that is not configured is still refused: the naming invariant holds.
	pub2 := strings.Repeat("cd", 32)
	if code, _ := bearerJSON(t, h, "POST", "/v1/register/apikey", "",
		fmt.Sprintf(`{"api_key":%q,"pub_key":%q,"name":"acme-a"}`, key, pub2)); code != http.StatusBadRequest {
		t.Fatalf("unconfigured org accepted: %d", code)
	}

	// Configure it, and the same enrollment now succeeds.
	if err := st.CreateOrg("acme", "op-1"); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if code, resp := bearerJSON(t, h, "POST", "/v1/register/apikey", "",
		fmt.Sprintf(`{"api_key":%q,"pub_key":%q,"name":"acme-a"}`, key, pub2)); code != http.StatusOK {
		t.Fatalf("enrollment under a stored org failed: %d (%s)", code, resp)
	}
	if m, _ := st.MachineByName("acme-a"); m == nil {
		t.Fatal("the machine was not created")
	}
}

// Longest-prefix resolution: "acme-2-host" belongs to org "acme-2", not "acme".
func TestOrgResolutionPrefersTheLongestPrefix(t *testing.T) {
	clearOIDCEnv(t)
	t.Setenv("MACH_ORGS", "")
	s, st := newAuthTestServer(t)
	if err := st.CreateOrg("acme", "op"); err != nil {
		t.Fatalf("create org: %v", err)
	}
	if err := st.CreateOrg("acme-2", "op"); err != nil {
		t.Fatalf("create org: %v", err)
	}
	org, ok := s.resolveOrgForName("acme-2-host")
	if !ok || org != "acme-2" {
		t.Fatalf("resolved %q (ok=%v), want acme-2", org, ok)
	}
}

// Membership groups keys honestly: scopes is a free string, so a key is not "in"
// an org — it either names that org's machines or it reaches every org.
func TestUIOrgMembershipSplitsKeys(t *testing.T) {
	s, st, _ := newUITestServer(t)
	if err := st.CreateMachine("acme-a", "pub-a", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.CreateMachine("other-b", "pub-b", "h", "linux", "amd64", "v", ""); err != nil {
		t.Fatalf("seed: %v", err)
	}
	if err := st.CreateAPIKey("scoped", "mach_"+store.RandToken(24), "exec:acme-a"); err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := st.CreateAPIKey("fleet", "mach_"+store.RandToken(24), "exec:*"); err != nil {
		t.Fatalf("key: %v", err)
	}
	if err := st.CreateAPIKey("watcher", "mach_"+store.RandToken(24), "readonly"); err != nil {
		t.Fatalf("key: %v", err)
	}
	// A key scoped to a different org must not appear as this org's.
	if err := st.CreateAPIKey("elsewhere", "mach_"+store.RandToken(24), "exec:other-b"); err != nil {
		t.Fatalf("key: %v", err)
	}

	data, err := s.orgMembership("acme")
	if err != nil {
		t.Fatalf("orgMembership: %v", err)
	}
	if len(data.Machines) != 1 || data.Machines[0].Name != "acme-a" {
		t.Fatalf("membership machines wrong: %+v", data.Machines)
	}
	if len(data.ScopedKeys) != 1 || data.ScopedKeys[0].Name != "scoped" {
		t.Fatalf("scoped keys wrong: %+v", data.ScopedKeys)
	}
	// exec:* and readonly reach every org, so they are listed as fleet-wide
	// rather than counted as members of this one.
	got := map[string]bool{}
	for _, k := range data.FleetKeys {
		got[k.Name] = true
	}
	if !got["fleet"] || !got["watcher"] {
		t.Fatalf("fleet-wide keys missing: %+v", data.FleetKeys)
	}
	for _, k := range append(append([]store.APIKeyInfo{}, data.ScopedKeys...), data.FleetKeys...) {
		if k.Name == "elsewhere" {
			t.Fatal("a key scoped to another org was listed as this org's")
		}
	}
}

// The static route is an allowlist, never a file server.
func TestUIStaticAllowlist(t *testing.T) {
	clearOIDCEnv(t)
	s, _ := newAuthTestServer(t)
	h := s.Routes()

	code, body := bearerJSON(t, h, "GET", "/static/htmx.min.js", "", "")
	if code != http.StatusOK || len(body) < 1000 {
		t.Fatalf("htmx.min.js did not serve: %d (%d bytes)", code, len(body))
	}
	for _, bad := range []string{"/static/app.js.bak", "/static/nope.js", "/static/../go.mod", "/static/", "/static/go.mod"} {
		if code, _ := bearerJSON(t, h, "GET", bad, "", ""); code == http.StatusOK {
			t.Fatalf("%s was served, want 404", bad)
		}
	}
}
