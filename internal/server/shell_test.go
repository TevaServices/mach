package server

// Tests for the page chrome: landmarks, heading structure, table semantics and
// the live regions.
//
// These are structural assertions rather than behavioural ones, and deliberately
// so — a screen reader's view of a page is built from exactly this markup, and
// nothing below the markup can see it. The fleet table's poll target is the
// cautionary example already in this package: a structural property that no
// behavioural test could catch, which is why it has a structural test of its own.

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
)

// uiGet fetches a path as a signed-in operator against a fresh UI server.
func uiGetPage(t *testing.T, h http.Handler, session *http.Cookie, path string) string {
	t.Helper()
	req := httptest.NewRequest("GET", path, nil)
	if session != nil {
		req.AddCookie(session)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("%s returned %d, want 200", path, rec.Code)
	}
	return rec.Body.String()
}

// Every operator page has exactly one h1, and it is the page's title.
//
// It used to have none at all: headings began at h2, so a screen reader's heading
// list started a level down with no statement of what page this was.
func TestUIPagesHaveExactlyOneH1(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, _ := uiSignIn(t, s, p)
	if err := st.CreateOrg("acme", "op-1"); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := st.CreateMachine("acme-web", "pub", "host", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed machine: %v", err)
	}

	for _, path := range []string{"/ui", "/ui/orgs", "/ui/orgs/acme"} {
		body := uiGetPage(t, h, session, path)
		if n := strings.Count(body, "<h1>"); n != 1 {
			t.Errorf("%s has %d h1 elements, want exactly 1", path, n)
		}
		// The h1 must carry the page's title, not a hardcoded string: the
		// sign-in pages used to hardcode "Sign-in unavailable" while the <title>
		// said something else, so the tab and the page disagreed.
		if !strings.Contains(body, "<h1>"+templateTitle(t, body)+"</h1>") {
			t.Errorf("%s: the h1 does not match the document title", path)
		}
	}

	// The public pages have one too, and the pair page is its own document.
	if body := uiGetPage(t, h, nil, "/"); strings.Count(body, "<h1>") != 1 {
		t.Error("the enrollment page does not have exactly one h1")
	}
}

// templateTitle pulls the text of the document's <title> element.
func templateTitle(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, "<title>")
	end := strings.Index(body, "</title>")
	if start < 0 || end < start {
		t.Fatalf("no <title> in the page")
	}
	return body[start+len("<title>") : end]
}

// The operator pages carry the landmarks and a skip link; the public enrollment
// page carries the landmarks but no skip link, because it has no navigation to
// skip past — a skip link whose target is the first thing on the page is noise.
func TestUIPagesHaveLandmarksAndASkipLink(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, _ := uiSignIn(t, s, p)
	if err := st.CreateMachine("bcross-a", "pub", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	page := uiGetPage(t, h, session, "/ui")
	for _, want := range []string{
		`<header class="site-header">`,
		`<main id="main">`,
		`class="skip-link" href="#main"`,
		`<nav aria-label="Main">`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the operator page is missing %s", want)
		}
	}

	// The version and the account block are one right-hand group, so the account
	// actions are rightmost. The old markup gave .who margin-left:auto and left
	// the version as its following sibling, which put the build string on the far
	// right and the account controls to its left.
	navRight := page[strings.Index(page, `class="nav-right"`):]
	if strings.Index(navRight, "mach-server") > strings.Index(navRight, "Sign out") {
		if strings.Contains(navRight, "Sign out") {
			t.Error("the version renders to the right of the account controls")
		}
	}

	pub := uiGetPage(t, h, nil, "/")
	if !strings.Contains(pub, `<main id="main">`) {
		t.Error("the public page is missing its main landmark")
	}
	if strings.Contains(pub, "skip-link") || strings.Contains(pub, "<header") {
		t.Error("the public enrollment page renders operator chrome")
	}
}

// aria-current marks the page you are on, and it is derived from which template
// rendered rather than from the page's title.
func TestUINavMarksTheCurrentPage(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, _ := uiSignIn(t, s, p)
	if err := st.CreateOrg("acme", "op-1"); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	fleet := uiGetPage(t, h, session, "/ui")
	if !strings.Contains(fleet, `href="/ui" aria-current="page"`) {
		t.Error("the Fleet link is not marked current on the fleet page")
	}
	if strings.Contains(fleet, `href="/ui/orgs" aria-current`) {
		t.Error("the Orgs link is marked current on the fleet page")
	}

	// An org's own page is the Orgs page, even though its title is "Org acme" —
	// which is exactly what keying the highlight off the title got wrong.
	org := uiGetPage(t, h, session, "/ui/orgs/acme")
	if !strings.Contains(org, `href="/ui/orgs" aria-current="page"`) {
		t.Error("the Orgs link is not marked current on an org's page")
	}
}

// The two live regions exist, carry the right roles, and the polled table is not
// one of them.
//
// The split is by urgency, not by looks: a refusal is the operator's own action
// coming back and should interrupt (role=alert), whereas a confirmation arriving
// a beat after a click should not (role=status).
func TestUINoticeRegionsAreLiveRegions(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, _ := uiSignIn(t, s, p)
	if err := st.CreateMachine("bcross-a", "pub", "h", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed: %v", err)
	}

	page := uiGetPage(t, h, session, "/ui")
	if !strings.Contains(page, `id="ui-error" role="alert"`) {
		t.Error("the error region is not an alert live region")
	}
	if !strings.Contains(page, `id="ui-notice" role="status"`) {
		t.Error("the notice region is not a status live region")
	}

	// The polled fragment must not carry either region, and must not be a live
	// region itself: it is replaced every five seconds, so announcing it would
	// repeat the whole fleet forever.
	poll := uiGetPage(t, h, session, "/ui/machines")
	for _, forbidden := range []string{`id="ui-error"`, `id="ui-notice"`, `hx-swap-oob`} {
		if strings.Contains(poll, forbidden) {
			t.Errorf("the polled fragment carries %s", forbidden)
		}
	}
	if !strings.Contains(poll, `id="fleet-table" aria-live="off"`) {
		t.Error("the polled table does not state that it is not a live region")
	}
}

// Every header cell says what it heads, and every data table has a caption.
func TestUITablesHaveScopedHeadersAndCaptions(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, _ := uiSignIn(t, s, p)
	if err := st.CreateOrg("acme", "op-1"); err != nil {
		t.Fatalf("seed org: %v", err)
	}
	if err := st.CreateMachine("acme-web", "pub", "host", "linux", "amd64", "v", "", false); err != nil {
		t.Fatalf("seed machine: %v", err)
	}

	for _, path := range []string{"/ui", "/ui/orgs", "/ui/orgs/acme", "/"} {
		body := uiGetPage(t, h, session, path)

		// The tag pattern is anchored so it cannot match <thead>: `<th` followed
		// by an optional attribute run and a closing bracket.
		thTag := regexp.MustCompile(`<th(?:\s[^>]*)?>`)
		tags := thTag.FindAllString(body, -1)
		if len(tags) == 0 {
			t.Errorf("%s: no <th> elements at all", path)
		}
		for _, tag := range tags {
			if !strings.Contains(tag, "scope=") {
				t.Errorf("%s: a <th> has no scope attribute: %s", path, tag)
			}
		}

		for _, tbl := range regexp.MustCompile(`(?s)<table>.*?</table>`).FindAllString(body, -1) {
			if !strings.Contains(tbl, "<caption") {
				t.Errorf("%s: a table has no caption", path)
			}
		}
	}
}

// The sealed-exec control is one form whose buttons state their own pressed
// state, so what is shown and what is announced cannot disagree.
func TestUISegmentedControlIsAccessible(t *testing.T) {
	s, st, p := newUITestServer(t)
	h := s.Routes()
	session, _ := uiSignIn(t, s, p)
	if err := st.CreateOrg("acme", "op-1"); err != nil {
		t.Fatalf("seed org: %v", err)
	}

	page := uiGetPage(t, h, session, "/ui/orgs/acme")
	if strings.Count(page, `id="orge2e"`) != 1 {
		t.Fatal("the org page does not render exactly one E2E control")
	}
	// Bounded at the next section heading rather than at end-of-page: the org
	// page now also carries the Remove-org form (memberSource), which is a form
	// but not part of this control.
	block := page[strings.Index(page, `id="orge2e"`):]
	if end := strings.Index(block, "<h2>Machines"); end >= 0 {
		block = block[:end]
	}

	if !strings.Contains(block, `role="group"`) {
		t.Error("the segmented control is not exposed as a group")
	}
	for _, want := range []string{
		`name="mode" value="on" aria-pressed=`,
		`name="mode" value="off" aria-pressed=`,
	} {
		if !strings.Contains(block, want) {
			t.Errorf("a segment is missing its pressed state: %s", want)
		}
	}
	// The pressed state is aria-pressed, not a parallel class: two sources of
	// truth for "which one is on" is how they end up disagreeing.
	if strings.Contains(block, `class="active"`) {
		t.Error("the segmented control still carries a parallel .active class")
	}
	// Exactly one form, so org/view/csrf are written once rather than three times.
	if n := strings.Count(block, "<form"); n != 1 {
		t.Errorf("the E2E control has %d forms, want 1", n)
	}
}
