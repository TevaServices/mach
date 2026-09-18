package server

// Tests for the org administration the UI exposes: the list, the membership
// view, and the per-org settings that live on an org's own page.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// E2E is per org, and the control for it lives on the org's own page: the list
// shows the value read-only, and the page offers the toggle plus the one thing a
// toggle cannot express — clearing the org's setting so it follows the default.
func TestUIOrgE2EOffTheListAndOntoTheOrgPage(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, csrf := uiSignIn(t, s, p)
	if err := st.CreateOrg("acme", "op-1"); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	// The list: shown, not set. The three buttons are gone.
	code, list, _ := uiPOST(t, h, session, csrf, "/ui/orgs/add", "org=zeta", true)
	if code != http.StatusOK {
		t.Fatalf("orgs fragment returned %d", code)
	}
	for _, gone := range []string{"E2E on", "E2E off", ">Inherit<", "Sealed exec"} {
		if strings.Contains(list, gone) {
			t.Errorf("the orgs list still carries %q; the control belongs on the org page", gone)
		}
	}
	// scope="col" is part of the assertion on purpose: the header cell has to say
	// which cells it heads, which is what lets a screen reader read the E2E column
	// as a column rather than as a list of loose values.
	if !strings.Contains(list, `<th scope="col">E2E</th>`) {
		t.Error("the orgs list no longer shows the E2E column header")
	}

	// The org's page: a control, and a statement of what is effective.
	req := httptest.NewRequest("GET", "/ui/orgs/acme", nil)
	req.AddCookie(session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("org page returned %d", rec.Code)
	}
	page := rec.Body.String()
	if !strings.Contains(page, `id="orge2e"`) || !strings.Contains(page, ">On<") {
		t.Fatalf("the org page has no E2E control:\n%s", page)
	}
	// No override yet, so it says so and offers the default-following statement
	// only where there is something to clear.
	if !strings.Contains(page, "follows the fleet default") {
		t.Error("the org page does not say this org follows the fleet default")
	}
	if strings.Contains(page, "Follow the fleet default") {
		t.Error("an org with no setting of its own is offered a control to clear one")
	}

	// Flipping it stores an override for this org only, and answers with the
	// control block so htmx swaps it in place.
	code, body, _ := uiPOST(t, h, session, csrf, "/ui/orgs/e2e", "org=acme&mode=off&view=member", true)
	if code != http.StatusOK {
		t.Fatalf("e2e off returned %d", code)
	}
	if !strings.Contains(body, `id="orge2e"`) {
		t.Errorf("the toggle did not return the control block:\n%s", body)
	}
	if mode, _ := E2EMode(st, "acme"); mode != e2eOff {
		t.Errorf("org acme E2E = %q, want off", mode)
	}
	// An override now exists, so clearing it is offered — and works.
	if !strings.Contains(body, "Follow the fleet default") {
		t.Errorf("an org with its own setting is not offered the way back to the default:\n%s", body)
	}
	if code, _, _ = uiPOST(t, h, session, csrf, "/ui/orgs/e2e", "org=acme&mode=inherit&view=member", true); code != http.StatusOK {
		t.Fatalf("follow-default returned %d", code)
	}
	if _, overridden := storedE2E(st, e2eOrgKey("acme")); overridden {
		t.Error("the org still has a setting of its own after clearing it")
	}
	// A plain (non-htmx) post from the org page comes back to that org, not to
	// the list it no longer carries the control on.
	code, _, rec = uiPOST(t, h, session, csrf, "/ui/orgs/e2e", "org=acme&mode=on&view=member", false)
	if code != http.StatusSeeOther {
		t.Fatalf("plain post returned %d, want 303", code)
	}
	if loc := rec.Header().Get("Location"); loc != "/ui/orgs/acme?n=e2eset" {
		t.Errorf("redirect to %q, want back to the org's page", loc)
	}
}
