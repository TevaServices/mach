package server

// Tests for the embedded assets and the stylesheet.
//
// Three properties are worth more than a smoke test here, because each one fails
// silently in production rather than loudly in a test:
//
//   - every asset URL carries a ?v= digest, or the immutable cache serves last
//     deploy's ui.css and app.js for a year;
//   - the pair page inlines the authored stylesheet instead of linking it, and
//     stays under `default-src 'none'`;
//   - the stylesheet keeps every colour in its token layer, which is the rule
//     that makes light/dark work on pages this control plane does not control
//     the environment of.

import (
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The shell's asset URLs must all carry the digest. Without it handleUIStatic's
// `max-age=31536000, immutable` means a browser that already holds app.js keeps
// it for a year — so a shipped fix to the pages' interactive behaviour would not
// reach an operator who had visited before, and the symptom would be the old
// behaviour with nothing in any log.
func TestUIPagesCarryCacheBustedAssets(t *testing.T) {
	s, _, p := newUITestServer(t)
	session, _ := uiSignIn(t, s, p)
	h := s.Routes()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ui", nil)
	req.AddCookie(session)
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("fleet page returned %d", rec.Code)
	}
	page := rec.Body.String()

	for _, want := range []string{
		`href="/static/ui.css?v=` + assetVersion + `"`,
		`src="/static/htmx.min.js?v=` + assetVersion + `"`,
		`src="/static/app.js?v=` + assetVersion + `"`,
	} {
		if !strings.Contains(page, want) {
			t.Errorf("the shell is missing %s", want)
		}
	}
	// The stylesheet is linked, not inlined: that is what lets one authored file
	// serve three pages without three copies of its text.
	if strings.Contains(page, "<style>") {
		t.Error("the shell still carries an inline <style> block")
	}
}

// The digest must actually be a digest of the bytes. A constant would satisfy the
// test above and defeat the entire point of it — the URL would change never, and
// the immutable cache would keep serving the first version forever.
func TestAssetVersionIsADigestOfTheAssets(t *testing.T) {
	if !regexp.MustCompile(`^[0-9a-f]{8}$`).MatchString(assetVersion) {
		t.Fatalf("assetVersion = %q, want 8 lowercase hex characters", assetVersion)
	}
	// Computed here as one concatenated buffer, where assets.go writes
	// incrementally, so the two expressions are genuinely independent rather than
	// the same line asserted against itself.
	all := append([]byte{}, mustAsset("static/htmx.min.js")...)
	all = append(all, mustAsset("static/app.js")...)
	all = append(all, uiCSSBytes...)
	sum := sha256.Sum256(all)
	if want := hex.EncodeToString(sum[:4]); assetVersion != want {
		t.Fatalf("assetVersion = %q, but the embedded bytes digest to %q", assetVersion, want)
	}
}

// The pair page is the one page that may not link a stylesheet: it keeps
// `default-src 'none'`, under which a <link> is blocked outright. It must inline
// the SAME authored bytes rather than a copy, or the two drift apart — which is
// exactly how the pages looked before this, each with its own hardcoded colours.
func TestPairPageInlinesTheStylesheet(t *testing.T) {
	s, st, _ := newUITestServer(t)
	h := s.Routes()

	_, token, _, err := st.CreatePairing("pub", "agent-host", "linux", "amd64", "v", 10*time.Minute)
	if err != nil {
		t.Fatalf("create pairing: %v", err)
	}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/pair/"+token, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("pair page returned %d, want 200", rec.Code)
	}
	body := rec.Body.String()

	if strings.Contains(body, `<link rel="stylesheet"`) {
		t.Error("the pair page links a stylesheet; its CSP blocks one")
	}
	// A token that exists only in the authored stylesheet, so its presence proves
	// the real file was spliced in rather than some subset of it.
	if !strings.Contains(body, ":focus-visible") {
		t.Error("the pair page does not inline the authored stylesheet")
	}
	csp := rec.Header().Get("Content-Security-Policy")
	if !strings.Contains(csp, "default-src 'none'") {
		t.Errorf("the pair page CSP lost its fail-closed default: %q", csp)
	}
	if strings.Contains(csp, "script-src") {
		t.Errorf("the pair page CSP permits script: %q", csp)
	}
}

// Colours live in the token layer and nowhere else.
//
// This is the rule that keeps dark mode working: `color-scheme: light dark` means
// a viewer's preference decides, and a literal #111 background is unreadable in
// one of the two. It is also how the enrollment page's download button and
// command block read on a dark screen before the tokens existed.
func TestStylesheetKeepsColourInItsTokenLayer(t *testing.T) {
	css := string(uiCSSBytes)

	// The layer order statement must precede the first block, or the layers are
	// declared in source order and a later edit silently reorders the cascade.
	order := strings.Index(css, "@layer tokens, base, layout, components, utilities;")
	if order < 0 {
		t.Fatal("ui.css has no layer order statement")
	}
	if firstBlock := strings.Index(css, "@layer tokens {"); firstBlock < order {
		t.Error("ui.css declares its layer blocks before its layer order")
	}
	// Every rule must sit inside a layer: an unlayered rule outranks all of them,
	// so one added outside a block would invisibly beat the whole file.
	if got := strings.Count(css, "@layer"); got < 6 {
		t.Errorf("ui.css has %d @layer occurrences, want the order statement plus five blocks", got)
	}

	tokensEnd := strings.Index(css, "@layer base")
	if tokensEnd < 0 {
		t.Fatal("ui.css has no @layer base block to bound the token layer")
	}
	// Any hex colour after the token layer is a literal that will not follow the
	// viewer's light/dark preference.
	hex := regexp.MustCompile(`#[0-9a-fA-F]{3,8}\b`)
	for _, loc := range hex.FindAllStringIndex(css, -1) {
		if loc[0] > tokensEnd {
			t.Errorf("colour literal %q appears outside the token layer at byte %d",
				css[loc[0]:loc[1]], loc[0])
		}
	}

	// No external fetches and no imports: the control plane serves these pages
	// from itself, and a CDN or a webfont would break the CSP and make the only
	// publicly reachable component depend on someone else's uptime.
	for _, banned := range []string{"@import", "url("} {
		if strings.Contains(css, banned) {
			t.Errorf("ui.css contains %q, which would fetch from outside this control plane", banned)
		}
	}
}

// The pages no longer need 'unsafe-inline' for styles, and must not quietly keep
// it.
//
// Three things had to be true together for this to be safe, and each is asserted
// here so a later edit cannot undo one of them in isolation:
//
//   - the shell links its stylesheet instead of carrying an inline <style>;
//   - htmx's indicator-style injection is off, because htmx otherwise writes an
//     inline <style> element that this policy would block;
//   - no template writes a style= attribute.
//
// 'unsafe-inline' for styles is not a theoretical widening: it is what lets
// injected markup reach CSS, which is a known exfiltration channel.
func TestUIRejectsInlineStyles(t *testing.T) {
	s, _, p := newUITestServer(t)
	session, _ := uiSignIn(t, s, p)
	h := s.Routes()

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/ui", nil)
	req.AddCookie(session)
	h.ServeHTTP(rec, req)

	csp := rec.Header().Get("Content-Security-Policy")
	if strings.Contains(csp, "unsafe-inline") {
		t.Errorf("the UI CSP still permits inline styles: %q", csp)
	}
	if !strings.Contains(csp, "style-src 'self'") {
		t.Errorf("the UI CSP does not permit the linked stylesheet: %q", csp)
	}

	// The enrollment page renders through the same shell, so a policy that was
	// tighter there than here would break a page the operator UI proves works.
	erec := httptest.NewRecorder()
	h.ServeHTTP(erec, httptest.NewRequest("GET", "/", nil))
	ecsp := erec.Header().Get("Content-Security-Policy")
	if strings.Contains(ecsp, "unsafe-inline") {
		t.Errorf("the enrollment page CSP still permits inline styles: %q", ecsp)
	}
	// The enrollment page must actually carry the linked stylesheet, or that
	// policy would leave it unstyled.
	if !strings.Contains(erec.Body.String(), "/static/ui.css?v=") {
		t.Error("the enrollment page does not link the stylesheet its CSP now requires")
	}

	// htmx must be told not to inject its own <style>, or the policy above blocks
	// it and any hx-indicator silently stops working.
	if !strings.Contains(rec.Body.String(), `"includeIndicatorStyles":false`) {
		t.Error("the shell does not switch off htmx's inline indicator styles")
	}

	// And nothing may write a style= attribute: under this policy it is inert, so
	// it would fail as a silently dropped style rather than as an error.
	for _, tmpl := range []struct{ name, src string }{
		{"shell", shellSource}, {"fleet", fleetSource}, {"fleettable", fleetInnerSource},
		{"orgs", orgsSource}, {"orge2e", orgE2ESource}, {"orgmember", memberSource},
		{"enroll", enrollSource}, {"enrollpick", enrollPickSource},
		{"pair", pairPageHead + pairPageCSS + pairPageBody},
	} {
		if strings.Contains(tmpl.src, `style="`) {
			t.Errorf("template %s writes a style= attribute, which its CSP refuses", tmpl.name)
		}
	}
}
