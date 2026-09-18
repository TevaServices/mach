package server

// HTTP handlers for the control-plane web UI.
//
// Two adapters, mirroring authConsole: uiGet for reads (session required, else a
// redirect to sign-in) and uiPost for state changes (session, same-site check,
// and a per-session CSRF token). Neither checks a scope: any verified identity
// may act, which is the configured policy — see SECURITY-NOTES.md for what that
// means and how to narrow it.

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"path/filepath"
	"strings"
	"time"

	"github.com/bcross/mach/internal/oidcauth"
	"github.com/bcross/mach/internal/store"
)

// uiHeaders are set on every UI response, fragments and redirects included: a
// fragment is still a response the browser processes, and leaving the headers off
// the state-changing requests would put the hole exactly where it matters most.
//
// The CSP is the one control this feature relaxes, and it is deliberately as
// narrow as htmx allows: no inline script, no eval. htmx drives everything
// through hx-* attributes; hx-on: and JS-valued hx-vals would both require
// 'unsafe-eval' and are not used anywhere in these pages. form-action 'self' is
// required because default-src 'none' falls back to it, and without it every
// form on the page is silently blocked.
//
// style-src is 'self' and NOT 'unsafe-inline'. It used to need the relaxation for
// the shell's inline <style> block; the styling is now a linked stylesheet
// (static/ui.css) and htmx's own indicator-style injection is switched off in the
// shell's htmx-config meta, so nothing on these pages writes a style this policy
// would refuse. That is a real narrowing rather than a tidy-up: 'unsafe-inline'
// for styles is reachable from injected markup, and it is what would let a
// stylesheet-based exfiltration trick work.
func uiHeaders(w http.ResponseWriter) {
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy",
		"default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; form-action 'self'")
}

// sameSiteRequest is the same defense-in-depth test the pair page applies to its
// POST: Sec-Fetch-Site must be same-origin, or absent (a non-browser client).
// It is not authentication — the session cookie and the synchronizer token are —
// but it refuses an obvious cross-site form post before anything else runs.
func sameSiteRequest(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "", "same-origin", "none":
		return true
	}
	return false
}

func (s *Server) uiSessionFrom(r *http.Request) (uiSession, bool) {
	if s.ui == nil {
		return uiSession{}, false
	}
	c, err := r.Cookie(uiSessionCookie)
	if err != nil {
		return uiSession{}, false
	}
	return s.ui.sessions.get(c.Value)
}

// uiGet requires a live session. There is deliberately no `next` parameter: a
// caller-supplied return path is an open redirect, and one extra click is not
// worth that class of bug.
func (s *Server) uiGet(next func(w http.ResponseWriter, r *http.Request, sess uiSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uiHeaders(w)
		if s.ui == nil {
			http.NotFound(w, r)
			return
		}
		sess, ok := s.uiSessionFrom(r)
		if !ok {
			http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
			return
		}
		next(w, r, sess)
	}
}

// uiPost guards a state-changing handler with three independent layers:
// the SameSite=Lax cookie (a cross-site POST carries no cookie at all), the
// same-site header check, and a per-session synchronizer token compared in
// constant time.
func (s *Server) uiPost(next func(w http.ResponseWriter, r *http.Request, sess uiSession)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		uiHeaders(w)
		if s.ui == nil {
			http.NotFound(w, r)
			return
		}
		sess, ok := s.uiSessionFrom(r)
		if !ok {
			http.Redirect(w, r, "/ui/login", http.StatusSeeOther)
			return
		}
		if !sameSiteRequest(r) {
			s.uiFail(w, r, http.StatusForbidden, "cross-site request refused")
			return
		}
		if err := r.ParseForm(); err != nil {
			s.uiFail(w, r, http.StatusBadRequest, "malformed form")
			return
		}
		tok := r.Header.Get("X-CSRF-Token")
		if tok == "" {
			tok = r.PostFormValue("csrf")
		}
		if subtle.ConstantTimeCompare([]byte(tok), []byte(sess.CSRF)) != 1 {
			s.uiFail(w, r, http.StatusForbidden, "missing or invalid csrf token")
			return
		}
		next(w, r, sess)
	}
}

// uiFail answers a refusal the way its caller can consume it.
//
// htmx gets the sentence as a fragment plus HX-Retarget, so it lands in the
// #ui-error live region and the operator actually sees it: htmx does not swap
// non-2xx responses by default, and app.js opts in only for a response that
// names a destination (see the htmx:beforeSwap listener there). Gating on the
// header rather than on the status is deliberate — it means a 500 from some path
// that still writes text/plain cannot be pasted into the page as markup.
//
// Everything else — a form post with scripting off, which is how these pages are
// meant to work without htmx — gets the same sentence on a real page through the
// shell. That replaces raw JSON dumped into the browser window, which is what a
// refusal used to look like to anyone without script.
//
// The status code is the caller's, unchanged in both branches. Making a refusal
// visible is not a reason to stop calling it a refusal, and scripts/e2e.sh
// asserts on these codes.
//
// The session is looked up rather than threaded through every call site: it is
// present for essentially every refusal (the guards in uiPost run after the
// session check), and having it means the page renders with the operator's nav
// and version instead of as anonymous chrome.
func (s *Server) uiFail(w http.ResponseWriter, r *http.Request, status int, msg string) {
	if r.Header.Get("HX-Request") != "" {
		w.Header().Set("HX-Retarget", "#ui-error")
		w.Header().Set("HX-Reswap", "innerHTML")
		s.renderFragmentStatus(w, uiSession{}, status, uiTmpl, "uierror", struct{ Msg string }{msg})
		return
	}
	sess, _ := s.uiSessionFrom(r)
	s.renderPage(w, status, sess, "", "That did not work", uiTmpl, "uierrorpage", struct{ Msg string }{msg})
}

// ---- pages ----

func (s *Server) handleUIFleet(w http.ResponseWriter, r *http.Request, sess uiSession) {
	rows, err := s.fleetRows()
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	notice := uiNoticeText(r.URL.Query().Get("n"))
	s.renderPage(w, http.StatusOK, sess, notice, "Fleet", uiTmpl, "fleet", fleetData{Rows: rows, CSRF: sess.CSRF})
}

// handleUIMachines serves the table fragment the page polls, so online, blocked
// and revoked state stays current without a reload.
//
// It is the *inner* region, not the container: a tick that replaced the
// container would take the Delete confirmation panel with it, which is exactly
// how a half-typed machine name used to disappear mid-confirmation.
func (s *Server) handleUIMachines(w http.ResponseWriter, r *http.Request, sess uiSession) {
	rows, err := s.fleetRows()
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	s.renderFragment(w, sess, uiTmpl, "fleettable", fleetData{Rows: rows, CSRF: sess.CSRF})
}

// handleUIConfirmClear empties the confirmation panel. It is a GET because
// dismissing a dialog changes nothing on the server, and it exists as a route
// rather than as a form button so the operator's Cancel does not have to submit
// the confirmation form to get out of it.
func (s *Server) handleUIConfirmClear(w http.ResponseWriter, r *http.Request, sess uiSession) {
	s.renderFragment(w, sess, uiTmpl, "confirmcleared", nil)
}

func (s *Server) handleUIOrgs(w http.ResponseWriter, r *http.Request, sess uiSession) {
	rows, err := s.orgRows()
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	notice := uiNoticeText(r.URL.Query().Get("n"))
	s.renderPage(w, http.StatusOK, sess, notice, "Orgs", uiTmpl, "orgs", orgsData{Rows: rows, CSRF: sess.CSRF})
}

func (s *Server) handleUIOrgMember(w http.ResponseWriter, r *http.Request, sess uiSession) {
	// Normalized exactly once, and up front, because orgRegistered lowercases
	// while the rest of this path is case-sensitive. Passing the raw path value
	// through meant `/ui/orgs/BCROSS` was accepted as a registered org and then
	// described a *different* one: no machines (nothing is named "BCROSS-…") and
	// the E2E setting of an org that does not exist, which falls back to the
	// default — so the page could report sealed commands as on for an org where
	// they are off. Its own On/Off buttons post the org the POST handler
	// lowercases, so the display and the action disagreed.
	org := strings.ToLower(strings.TrimSpace(r.PathValue("org")))
	if !s.orgRegistered(org) {
		http.NotFound(w, r)
		return
	}
	data, err := s.orgMembership(org)
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	data.CSRF = sess.CSRF
	s.renderPage(w, http.StatusOK, sess, "", "Org "+org, uiTmpl, "orgmember", data)
}

// ---- machine actions ----

func (s *Server) handleUIBlock(w http.ResponseWriter, r *http.Request, sess uiSession) {
	s.uiSetBlock(w, r, sess, true)
}

func (s *Server) handleUIUnblock(w http.ResponseWriter, r *http.Request, sess uiSession) {
	s.uiSetBlock(w, r, sess, false)
}

func (s *Server) uiSetBlock(w http.ResponseWriter, r *http.Request, sess uiSession, blocked bool) {
	name := r.PostFormValue("machine")
	if err := s.blockMachine(name, blocked); err != nil {
		status, msg := http.StatusInternalServerError, "The database could not be read. Nothing was changed."
		if errors.Is(err, errNoSuchMachine) {
			status, msg = http.StatusNotFound, "No machine by that name."
		}
		s.uiFail(w, r, status, msg)
		return
	}
	action := "unblock"
	if blocked {
		action = "block"
	}
	s.auditUIAction(name, action, sess.Ident, blockVerb(blocked)+" via the web UI")
	s.logf("ui: machine %s: %q (by %q)", blockVerb(blocked), name, sess.Ident.Subject)
	s.refreshOrRedirect(w, r, sess, action+"ed")
}

func (s *Server) handleUIRevoke(w http.ResponseWriter, r *http.Request, sess uiSession) {
	name := r.PostFormValue("machine")
	m, err := s.st.MachineByName(name)
	if err != nil || m == nil {
		s.uiFail(w, r, http.StatusNotFound, "No machine by that name.")
		return
	}
	// No purge_audit from the UI: erasing another machine's command history stays
	// an explicit CLI act, exactly as it is for delete.
	if err := s.revokeMachine(name, false); err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	s.auditUIAction(name, "revoke", sess.Ident, "revoked via the web UI — name and key stay reserved")
	s.logf("ui: machine revoked: %q (by %q)", name, sess.Ident.Subject)
	s.refreshOrRedirect(w, r, sess, "revoked")
}

func (s *Server) handleUIDelete(w http.ResponseWriter, r *http.Request, sess uiSession) {
	name := r.PostFormValue("machine")
	m, err := s.st.MachineByName(name)
	if err != nil || m == nil {
		s.uiFail(w, r, http.StatusNotFound, "No machine by that name.")
		return
	}

	// Typed-name confirmation. A dialog would be one click through; delete is the
	// action that removes the tombstone stopping a stolen key from re-enrolling,
	// and it must not be reachable by a misclick on the wrong row.
	//
	// The confirmation is a fragment for htmx and a PAGE for everyone else. It
	// used to be the fragment unconditionally, so with scripting off the browser
	// navigated to a bare panel with no shell, no navigation and no way back —
	// the Delete button, the one action that must not be reachable by a misclick,
	// was the one that stranded you. TestUIDeleteRequiresTypedName only ever
	// exercised the htmx path, which is why it stayed green.
	confirmName := r.PostFormValue("confirm_name")
	if r.PostFormValue("confirm") != "1" || confirmName != name {
		data := deleteConfirmData{
			Name: name, Online: m.Name != "" && s.agentOnline(name), CSRF: sess.CSRF,
		}
		if r.Header.Get("HX-Request") != "" {
			s.renderFragment(w, sess, uiTmpl, "deleteconfirm", data)
			return
		}
		s.renderPage(w, http.StatusOK, sess, "", "Delete "+name, uiTmpl, "deleteconfirmpage", data)
		return
	}

	// The row goes first, then the notice, then the close: see deleteMachine.
	if err := s.deleteMachine(name); err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	// Audited after the row is gone, deliberately: audit has no foreign key to
	// machines and DeleteMachine keeps the trail, so "who deleted this" stays
	// discoverable through /v1/audit?machine=<name>.
	s.auditUIAction(name, "delete machine", sess.Ident, "deleted via the web UI — name and key freed")
	s.logf("ui: machine deleted: %q (by %q) — name and key are free to re-enroll", name, sess.Ident.Subject)
	s.refreshOrRedirect(w, r, sess, "deleted")
}

// refreshOrRedirect answers the way the caller can consume: an htmx request gets
// the refreshed table to swap in, a plain form post gets a redirect. The htmx
// attributes are an enhancement, not a requirement — these pages work with
// scripting unavailable.
//
// The htmx branch renders "fleetaction" rather than "fleet": that is the same
// container plus the out-of-band notice. Without it the eight sentences in
// uiNotices were reachable only by a scripting-off browser, so with htmx on — the
// normal case — a successful block, revoke or delete produced no confirmation at
// all. Both branches take their sentence from uiNoticeText, so the two paths
// cannot say different things.
func (s *Server) refreshOrRedirect(w http.ResponseWriter, r *http.Request, sess uiSession, noticeCode string) {
	if r.Header.Get("HX-Request") != "" {
		rows, err := s.fleetRows()
		if err != nil {
			s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
			return
		}
		s.renderFragment(w, sess, uiTmpl, "fleetaction", fleetData{
			Rows: rows, CSRF: sess.CSRF, Notice: uiNoticeText(noticeCode),
		})
		return
	}
	http.Redirect(w, r, "/ui?n="+noticeCode, http.StatusSeeOther)
}

func (s *Server) agentOnline(name string) bool {
	online := s.br.OnlineNames()
	return online[name]
}

// auditUIAction records an operator action in the per-machine audit trail. The
// command string is a fixed literal and the reason is server-authored, so no
// request-derived text reaches the audit row.
func (s *Server) auditUIAction(machine, action string, ident oidcauth.Identity, detail string) {
	src := "ui"
	if ident.Subject != "" {
		src = "ui:" + ident.Subject
	}
	// Auditing is best-effort: an operator's action already took effect, and
	// failing the request because the trail could not be written would leave the
	// UI reporting an error for something that did happen.
	if err := s.st.AuditInsert(nowRFC3339(), machine, action, src, sqlNullInt(0), "", detail); err != nil {
		s.logf("ui: audit write failed for %s on %q: %v", action, machine, err)
	}
}

// ---- sign-in ----

func (s *Server) handleUILogin(w http.ResponseWriter, r *http.Request) {
	uiHeaders(w)
	if s.ui == nil {
		http.NotFound(w, r)
		return
	}
	if s.ui.loginRate.record(s.clientIP(r)) {
		s.renderSignInMessage(w, http.StatusTooManyRequests, "Too many sign-in attempts", "Try again later.")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), uiProviderTimeout)
	defer cancel()
	p, err := s.ui.providerFor(ctx)
	if err != nil {
		s.logf("ui: identity provider unreachable: %v", err)
		s.renderSignInMessage(w, http.StatusServiceUnavailable, "Sign-in unavailable",
			"The identity provider could not be reached. Nothing about this fleet was changed.")
		return
	}

	state, nonce, binding := store.RandToken(32), store.RandToken(32), store.RandToken(32)
	if !s.ui.logins.put(state, uiLoginState{Nonce: nonce, Binding: binding, Expires: time.Now().Add(uiStateTTL)}) {
		s.renderSignInMessage(w, http.StatusServiceUnavailable, "Sign-in unavailable",
			"Too many sign-ins are already in flight. Try again shortly.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: uiStateCookie, Value: binding, Path: "/ui", HttpOnly: true,
		Secure: s.ui.cookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(uiStateTTL.Seconds()),
	})
	http.Redirect(w, r, p.AuthCodeURL(state, nonce), http.StatusFound)
}

func (s *Server) handleUICallback(w http.ResponseWriter, r *http.Request) {
	uiHeaders(w)
	if s.ui == nil {
		http.NotFound(w, r)
		return
	}
	if s.ui.callbackRate.record(s.clientIP(r)) {
		s.renderSignInMessage(w, http.StatusTooManyRequests, "Sign-in unavailable", "Too many attempts. Try again later.")
		return
	}
	q := r.URL.Query()
	if e := q.Get("error"); e != "" {
		// The provider's error_description is provider-controlled text: log it,
		// never render it.
		s.logf("ui: identity provider returned error=%q", e)
		s.renderSignInMessage(w, http.StatusBadRequest, "Sign-in refused",
			"The identity provider refused the sign-in.")
		return
	}
	state, code := q.Get("state"), q.Get("code")
	if state == "" || code == "" {
		s.renderSignInMessage(w, http.StatusBadRequest, "Sign-in link incomplete",
			"This sign-in link is missing its state or code.")
		return
	}
	st, ok := s.ui.logins.peek(state)
	if !ok {
		s.renderSignInMessage(w, http.StatusBadRequest, "Sign-in link expired",
			"This sign-in link has already been used or has expired. Start again.")
		return
	}
	// Bind the callback to the browser that began it. Without this an attacker
	// could complete a sign-in in someone else's browser, leaving the victim
	// acting as the attacker's identity (login CSRF).
	//
	// Checked before the state is consumed, so a callback that fails here does not
	// burn the state the operator's own browser is about to use.
	c, err := r.Cookie(uiStateCookie)
	if err != nil || subtle.ConstantTimeCompare([]byte(c.Value), []byte(st.Binding)) != 1 {
		s.renderSignInMessage(w, http.StatusBadRequest, "Sign-in did not start here",
			"This sign-in did not start in this browser. Start again.")
		return
	}
	// Past the binding check, the state is spent: a replayed callback finds
	// nothing, so a captured authorization code cannot be exchanged twice.
	s.ui.logins.consume(state)
	http.SetCookie(w, &http.Cookie{
		Name: uiStateCookie, Value: "", Path: "/ui", HttpOnly: true,
		Secure: s.ui.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})

	ctx, cancel := context.WithTimeout(r.Context(), uiProviderTimeout)
	defer cancel()
	p, err := s.ui.providerFor(ctx)
	if err != nil {
		s.logf("ui: identity provider unreachable at callback: %v", err)
		s.renderSignInMessage(w, http.StatusServiceUnavailable, "Sign-in unavailable",
			"The identity provider could not be reached.")
		return
	}
	ident, err := p.Exchange(ctx, code, st.Nonce)
	if err != nil {
		// The verifier's message says which check failed, which is what an
		// operator needs in the log; it is not rendered, because it can embed
		// provider-supplied text.
		s.logf("ui: sign-in verification failed: %v", err)
		s.renderSignInMessage(w, http.StatusUnauthorized, "Sign-in could not be verified",
			"The identity token was refused. Nothing about this fleet was changed.")
		return
	}

	token, _, ok := s.ui.sessions.create(ident)
	if !ok {
		s.renderSignInMessage(w, http.StatusServiceUnavailable, "Sign-in unavailable",
			"Too many operators are signed in. Try again shortly.")
		return
	}
	http.SetCookie(w, &http.Cookie{
		Name: uiSessionCookie, Value: token, Path: "/ui", HttpOnly: true,
		Secure: s.ui.cookieSecure, SameSite: http.SameSiteLaxMode,
		MaxAge: int(uiSessionTTL.Seconds()),
	})
	s.logf("ui: signed in: sub=%q email=%q", ident.Subject, ident.Email)
	http.Redirect(w, r, "/ui", http.StatusSeeOther)
}

func (s *Server) handleUILogout(w http.ResponseWriter, r *http.Request, sess uiSession) {
	if c, err := r.Cookie(uiSessionCookie); err == nil {
		s.ui.sessions.delete(c.Value)
	}
	http.SetCookie(w, &http.Cookie{
		Name: uiSessionCookie, Value: "", Path: "/ui", HttpOnly: true,
		Secure: s.ui.cookieSecure, SameSite: http.SameSiteLaxMode, MaxAge: -1,
	})
	s.logf("ui: signed out: sub=%q", sess.Ident.Subject)
	// A message page rather than a redirect to /ui/login: with a live identity
	// provider session, bouncing straight back into the sign-in flow would sign
	// the operator in again and make "sign out" look broken.
	s.renderSignInMessage(w, http.StatusOK, "Signed out", "You have been signed out of this browser.")
}

// renderSignInMessage renders a page shown when there is no session: a fixed
// server-authored sentence, never provider or request text.
func (s *Server) renderSignInMessage(w http.ResponseWriter, status int, title, reason string) {
	s.renderPage(w, status, uiSession{}, "", title, uiTmpl, "loginfailed", struct{ Reason string }{reason})
}

// ---- static assets ----

// knownStaticFiles is a strict allowlist, mirroring knownAgentFiles for agent
// downloads: an explicit map, never a file server over a directory.
//
// The embed itself and the cache-busting digest live in assets.go.
var knownStaticFiles = map[string]string{
	"htmx.min.js": "text/javascript; charset=utf-8",
	"app.js":      "text/javascript; charset=utf-8",
	"ui.css":      "text/css; charset=utf-8",
}

func (s *Server) handleUIStatic(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.PathValue("file"))
	ct, ok := knownStaticFiles[name]
	if !ok {
		http.NotFound(w, r)
		return
	}
	b, err := staticFiles.ReadFile("static/" + name)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	h := w.Header()
	h.Set("Content-Type", ct)
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "public, max-age=31536000, immutable")
	_, _ = w.Write(b)
}
