package server

import (
	"html/template"
	"net/http"
	"strconv"
	"strings"

	"github.com/bcross/mach/internal/store"
)

// Minimal phone-facing approve page. Not for human dashboards.
//
// Security properties:
//   - The challenge code is NEVER displayed on this page, and it is not in the
//     QR either. The human must type the code they read on the agent's console
//     (anti-QR-theft: a photo of just the QR is useless). The QR carries the org
//     and a *suggested* machine name so the operator has less to type, but the
//     one secret — the code — travels by a channel the phone does not have:
//     the target machine's own screen, read by a person standing at it.
//   - The suggested name comes from the enrolling agent's hostname, which is
//     agent-reported text. It is a starting point in an editable field, shown
//     under a heading that says where it came from, and the name the operator
//     submits is validated exactly as it was before suggestions existed
//     (store.ValidOrgName + the enrollment policy). What changed is only the
//     default in a box; what did not is that nothing here is trusted.
//   - Wrong code attempts are counted; 5 wrong attempts expire the pairing.
//   - Security headers set on every response. The page stays under
//     `default-src 'none'` with no script at all: it is reached by scanning a
//     code, so it must not need a script engine to be safe on a phone.
//
// The styling is the control plane's own (uiBaseCSS), embedded rather than
// fetched. A page reached from a QR code should not look like a different
// product from the fleet the operator is about to manage, and sharing one CSS
// source is what keeps them from drifting apart again.

const pairPageTmpl = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>mach — approve machine</title>
<style>` + uiBaseCSS + `
.pair { max-width: 30rem; margin-inline: auto; padding-top: 1.5rem; }
.pair h2 { margin-top: 0; }
.pair .field { display: block; margin: 1.1rem 0; }
.pair .field > span { display: block; font-size: .85rem; color: var(--muted); margin-bottom: .25rem; }
.pair input[type=text], .pair select { width: 100%; font-size: 1.05rem; padding: .5rem .55rem; }
.pair .code { letter-spacing: .18em; text-transform: uppercase; font-size: 1.25rem; }
.pair .actions { display: flex; gap: .6rem; margin: 1.5rem 0 0; }
.pair .actions .btn-primary { flex: 1; }
</style>
</head><body>
<main class="pair">
<h2>mach — approve machine</h2>
{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
{{if .Done}}
<div class="panel">
<p>✅ Machine approved and named <b>{{.Name}}</b>.</p>
<p class="muted">The agent on that machine will finish enrollment within a few seconds.</p>
</div>
{{else if .Terminal}}
<p>Pairing state: <b>{{.State}}</b></p>
{{else}}
<p><b>New agent requesting enrollment</b>. The details below are what that
machine reported about itself — verify out-of-band that a new machine is
actually being set up.</p>
<table>
<tr><td class="muted">reports hostname</td><td>{{.Hostname}}</td></tr>
<tr><td class="muted">reports platform</td><td>{{.OS}}/{{.Arch}} — agent {{.AgentVer}}</td></tr>
</table>
<form method="POST" action="/pair/{{.Token}}">
<p class="muted">Type the <b>challenge code shown on the agent's console</b> — the
12 characters printed on the machine being enrolled. It is deliberately not in
this page and not in the QR code. The dashes are optional.</p>
<label class="field"><span>Challenge code</span>
<input class="code" type="text" name="code" autocomplete="off" autocapitalize="characters"
 spellcheck="false" required minlength="12" maxlength="19" autofocus
 placeholder="XXXX-XXXX-XXXX"></label>
<label class="field"><span>Org — the prefix this machine's name carries</span>
<select name="org" required>
{{range .Orgs}}<option value="{{.}}"{{if eq . $.Org}} selected{{end}}>{{.}}</option>{{end}}
</select></label>
<label class="field"><span>Machine name — the full name will be <code>&lt;org&gt;-&lt;machine&gt;</code></span>
<input type="text" name="name" required value="{{.NamePart}}" autocomplete="off"
 spellcheck="false" maxlength="48" placeholder="web-01"></label>
{{if .Suggested}}<p class="muted">The org and name above were suggested by the
agent on that machine (from its hostname). Edit either one if they are wrong.</p>{{end}}
<p class="actions">
<button class="btn-primary" type="submit" name="approve" value="1">Approve</button>
<button type="submit" name="deny" value="1">Deny</button>
</p>
</form>
<p class="muted">5 wrong code attempts expire this pairing. Only approve if you
personally started enrollment on that machine.</p>
{{end}}
</main>
</body></html>`

var pairTmpl = template.Must(template.New("pair").Parse(pairPageTmpl))

type pairPageData struct {
	Error    string
	Done     bool
	Name     string
	State    string
	Hostname string
	OS       string
	Arch     string
	AgentVer string
	Token    string
	Orgs     []string
	// Org is the org the form starts on, and NamePart the machine-name part it
	// starts with. They arrive from the QR's query string (the enrolling agent's
	// suggestion) or, on a retry, from what the operator just submitted — so a
	// refused approval does not make them type it all again.
	Org       string
	NamePart  string
	Suggested bool
	// Terminal is set for a pairing that can no longer be approved (approved,
	// denied, expired). It is what decides whether the form is rendered, rather
	// than the State string being non-empty: a retry after a wrong code also
	// carries a State, and reading that as terminal is how a single typo used to
	// leave the operator looking at an error with no form to correct it in.
	Terminal bool
}

func (s *Server) pairPageHandler(w http.ResponseWriter, r *http.Request) {
	// Security headers on every pair-page response. Note what is NOT here:
	// script-src. This page needs no script, so it keeps the strictest policy in
	// the codebase even though it renders in the control plane's own styling.
	h := w.Header()
	h.Set("X-Frame-Options", "DENY")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'")

	// Bounded per IP (generous: a human with a slow connection is nowhere
	// close). This page is reachable by anyone, so the bound is also what
	// keeps a scanner from probing pairing tokens at speed.
	if s.pairLookups.record(s.clientIP(r)) {
		http.Error(w, "too many requests — try again in a few minutes", http.StatusTooManyRequests)
		return
	}

	token := r.PathValue("token")
	p, err := s.st.PairingByToken(token)
	if err != nil || p == nil {
		http.Error(w, "unknown pairing link", http.StatusNotFound)
		return
	}
	state := s.st.PairingState(p)

	if r.Method == http.MethodPost {
		// Defense in depth, not the authentication: the token in the path is
		// the secret, and whoever holds it can post directly. This stops a
		// page on another site from driving an approve in a browser that
		// happens to have this pairing open. Sec-Fetch-Site is used rather
		// than comparing Origin to Host because it is sent by every browser
		// and cannot be confused by a TLS-terminating proxy rewriting Host.
		if site := r.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "cross-site approval is not allowed — open the pairing link directly", http.StatusForbidden)
			return
		}
		s.handlePairPost(w, r, p, state, token)
		return
	}

	switch state {
	case "approved", "denied", "expired":
		renderPair(w, terminalPair(state, p.Name))
	default:
		org := s.suggestedOrg(r.URL.Query().Get("org"))
		part := suggestedNamePart(r.URL.Query().Get("name"))
		renderPair(w, pairPageData{
			Hostname: p.Hostname, OS: p.OS, Arch: p.Arch, AgentVer: p.AgentVer,
			Token: token, Orgs: s.ListOrgs(),
			Org: org, NamePart: part,
			// Only claimed when something actually arrived: a pairing link opened
			// without the query string (a hand-typed URL, an older agent binary)
			// gets the same page it always did, with no line explaining a
			// suggestion that is not there.
			Suggested: org != "" || part != "",
		})
	}
}

// suggestedOrg returns the org the QR suggested, but only if this control plane
// actually has it configured. A value that is not configured is dropped rather
// than shown pre-selected: the page's org control only offers real orgs, so
// pre-selecting something absent from it would leave the operator looking at a
// different org than the one they were told, with no indication why.
func (s *Server) suggestedOrg(v string) string {
	org := strings.ToLower(strings.TrimSpace(v))
	if org == "" || !s.orgRegistered(org) {
		return ""
	}
	return org
}

// suggestedNamePart returns the machine-name suggestion to show, or "" when the
// query value is not something a machine name may contain.
//
// It *validates* rather than rewrites, and it asks store.ValidMachinePart — the
// same rule the store applies when the form is submitted. That is deliberate on
// both counts: a second normalizer here would be a second rule, and a
// suggestion this page shows is one the operator is invited to accept, so it
// must be one the store will take. A value that fails is dropped and the field
// starts empty, which is the honest outcome and the one that needs no
// explanation to read.
//
// None of this is trust. The suggestion comes from the enrolling agent
// (a hostname), so it is agent-reported text: it is shown in an editable box
// under a line saying where it came from, and the submitted name goes through
// enrollmentRefusal and the store exactly as it did before suggestions existed.
func suggestedNamePart(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if !store.ValidMachinePart(v) {
		return ""
	}
	return v
}

func (s *Server) handlePairPost(w http.ResponseWriter, r *http.Request, p *store.Pairing, state, token string) {
	// token is the raw bearer token from the URL path — retry/error renders
	// reuse it so the retry form posts back to the same working link.
	if err := r.ParseForm(); err != nil {
		http.Error(w, "bad form", http.StatusBadRequest)
		return
	}
	if r.FormValue("deny") == "1" {
		// Terminal, and rendered the way every other terminal state is. Without
		// the flag the template fell through to its form branch, so a denial
		// answered with the approve form again: the operator could not tell the
		// denial had taken effect, and the form it was shown posts to a path with
		// no token, which does not route. The name is included so the page can say
		// which pairing was denied.
		if changed, err := s.st.DenyPairing(p.ID); err == nil && changed {
			renderPair(w, terminalPair("denied", p.Name))
		} else {
			renderPair(w, terminalPair(s.st.PairingState(p), p.Name))
		}
		return
	}
	if state != "pending" {
		renderPair(w, terminalPair(state, p.Name))
		return
	}
	code := normalizeCode(r.FormValue("code"))
	org := strings.ToLower(strings.TrimSpace(r.FormValue("org")))
	machinePart := strings.TrimSpace(r.FormValue("name"))
	name := org + "-" + machinePart

	// Everything the operator typed is handed back on a refusal, so a wrong code
	// does not also cost them the org and the name.
	retry := func(msg string) pairPageData {
		return pairPageData{
			Error: msg, State: "pending-retry", Token: token, Orgs: s.ListOrgs(),
			Org: org, NamePart: machinePart,
		}
	}

	// Org must be a registered org, and the composed name must satisfy the
	// org-prefix rule. Conflicts error out and require a new name.
	if !s.orgRegistered(org) {
		renderPair(w, retry("Unknown org "+strconv.Quote(org)+" — pick one from the list."))
		return
	}
	if !store.ValidOrgName(org, name) {
		renderPair(w, retry("Machine part must be 1-48 chars (letters/digits/hyphen). Final name: "+org+"-<machine>."))
		return
	}
	// Whether this name may be taken is the enrollment policy's call, not this
	// page's. A revoked or temporary row may be taken over (see store.reenroll),
	// and a second copy of that rule living here is exactly how the QR path came
	// to disagree with the API-key path — this check refused a name the store
	// would have accepted, so a temporary session could retire itself and then
	// never come back under its own name.
	if status, msg := s.enrollmentRefusal(name, p.PubKey); status != 0 {
		renderPair(w, retry(msg+" Final name: "+name+"."))
		return
	}

	ok, why, err := s.st.ApprovePairing(p.ID, code, name)
	if err != nil {
		http.Error(w, "store error", http.StatusInternalServerError)
		return
	}
	if !ok {
		if why == "bad-code" {
			// Count the attempt; expire the pairing after 5 wrong tries.
			alive, aerr := s.st.RecordPairingAttempt(p.ID, 5)
			if aerr != nil || !alive {
				renderPair(w, pairPageData{Error: "Too many wrong code attempts — this pairing is expired. Run enrollment again on the machine.", State: "expired", Terminal: true})
				return
			}
			renderPair(w, retry("Wrong code. Do not approve unless you can read the agent's console."))
			return
		}
		if why == "not-pending" {
			// A concurrent deny/expiry won the race; show the real state.
			renderPair(w, terminalPair(s.st.PairingState(p), p.Name))
			return
		}
		renderPair(w, terminalPair(why, p.Name))
		return
	}
	s.logf("pair approved: id=%q name=%q", p.ID, name)
	renderPair(w, pairPageData{Done: true, Name: name})
}

// terminalPair is the page for a pairing that is no longer pending: it shows the
// state and renders no form, because there is nothing left to submit.
func terminalPair(state, name string) pairPageData {
	return pairPageData{State: state, Name: name, Terminal: true}
}

func renderPair(w http.ResponseWriter, data pairPageData) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_ = pairTmpl.Execute(w, data)
}

// normalizeCode uppercases and strips separators so XXXX-XXXX-XXXX can be
// typed with or without dashes/spaces.
// normalizeCode is the display-form normalization, kept as a local name so the
// page reads the same as before. It delegates to the store, which is where the
// hashing happens: these two agreeing is the whole point, and they have not
// always — see store.NormalizeCode.
func normalizeCode(s string) string { return store.NormalizeCode(s) }
