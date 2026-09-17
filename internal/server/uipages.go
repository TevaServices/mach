package server

// Templates for the control-plane web UI, and for the enrollment page that now
// renders through the same shell.
//
// These are inline html/template sources parsed at package init, matching the
// pair and enrollment pages that were already here. There is no template
// directory, no build step and no embedded filesystem for markup: the pages
// travel inside the binary.
//
// Two things every template here depends on:
//
//   - html/template's contextual escaping is the only thing standing between
//     agent-reported text (hostname, os, arch, agent_version) and the page. A
//     compromised agent controls those fields, so they are never used to build
//     URLs or attribute values.
//   - The Content-Security-Policy in uiHeaders permits no inline script and no
//     eval. Everything interactive is an hx-* attribute; hx-on: and JS-valued
//     hx-vals would both require 'unsafe-eval'.

import (
	"bytes"
	"html/template"
	"net/http"

	"github.com/bcross/mach/internal/version"
)

// uiBaseCSS is the visual language every page this control plane serves shares:
// the signed-in UI, the public enrollment page (which renders through the same
// shell), and the phone-facing pair page. The pair page cannot use the shell —
// it is reached from a QR code by an anonymous visitor and keeps its strict
// `default-src 'none'`, so it must not load htmx or app.js — so the styling
// lives here and both embed it. That is what stops the two from looking like
// different products, which is how they looked when each carried its own
// hardcoded colours.
//
// Colour goes through custom properties rather than literals because every page
// honours the viewer's light/dark preference (`color-scheme: light dark`) and a
// hardcoded #111 background is unreadable in one of the two — which is exactly
// how the enrollment page's download button and command block read on a dark
// screen before this.
const uiBaseCSS = `
:root {
  color-scheme: light dark;
  --fg: #16181d; --bg: #ffffff;
  --muted: #6b7280; --line: #8883; --panel: #8881;
  --accent-bg: #16181d; --accent-fg: #ffffff;
  --ok: #1a7f37; --warn: #a06000; --bad: #b3261e;
}
@media (prefers-color-scheme: dark) {
  :root {
    --fg: #e6e8ec; --bg: #14161a;
    --muted: #9aa1ab; --line: #8884; --panel: #8882;
    --accent-bg: #e6e8ec; --accent-fg: #14161a;
    --ok: #4ac26b; --warn: #d29922; --bad: #f85149;
  }
}
* { box-sizing: border-box; }
body { font-family: -apple-system, system-ui, sans-serif; margin: 0; padding: 0 1rem 3rem;
       max-width: 64rem; margin-inline: auto; line-height: 1.45;
       background: var(--bg); color: var(--fg); }
nav { display: flex; flex-wrap: wrap; gap: 1rem; align-items: center;
      padding: 1rem 0; border-bottom: 1px solid var(--line); margin-bottom: 1.5rem; }
nav a { text-decoration: none; color: inherit; font-weight: 600; }
nav a[aria-current] { text-decoration: underline; }
nav .who { margin-left: auto; font-size: .85rem; color: var(--muted); }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: .45rem .6rem; border-bottom: 1px solid var(--line);
         vertical-align: top; }
th { font-size: .8rem; text-transform: uppercase; letter-spacing: .04em; color: var(--muted); }
.badge { display: inline-block; font-size: .75rem; padding: .05rem .4rem;
         border: 1px solid currentColor; border-radius: .6rem; margin-right: .25rem; }
.online { color: var(--ok); } .offline { color: var(--muted); }
.blocked { color: var(--warn); } .revoked { color: var(--bad); }
.pinned { color: var(--muted); }
.error { color: var(--bad); font-weight: 600; }
button { font: inherit; padding: .3rem .7rem; cursor: pointer; border-radius: .3rem;
         border: 1px solid var(--line); background: transparent; color: inherit; }
form.inline { display: inline; }
.notice { padding: .6rem .8rem; border: 1px solid var(--line); border-radius: .3rem;
          margin-bottom: 1rem; }
.muted { color: var(--muted); font-size: .85rem; }
code { background: var(--panel); padding: .05rem .3rem; border-radius: .2rem; }
input[type=text], select { font: inherit; padding: .3rem .4rem; }
.row-actions { display: flex; flex-wrap: wrap; gap: .3rem; }
.panel { border: 1px solid var(--line); border-radius: .4rem; padding: .9rem 1.1rem;
         margin: 1rem 0; background: var(--panel); }
.btn-primary { display: inline-block; font-size: 1.05rem; font-weight: 600;
               padding: .6rem 1.2rem; border: 0; border-radius: .3rem;
               background: var(--accent-bg); color: var(--accent-fg);
               text-decoration: none; cursor: pointer; }
.seg { display: inline-flex; vertical-align: middle; border: 1px solid var(--line);
       border-radius: .3rem; overflow: hidden; }
.seg button { border: 0; border-radius: 0; padding: .35rem .95rem; background: transparent; }
.seg button.active { background: var(--accent-bg); color: var(--accent-fg); font-weight: 600; }
.e2e-row { display: flex; flex-wrap: wrap; gap: .6rem; align-items: center; }
`

// View models. The row types live next to the code that assembles them
// (fleetRow in machineadmin.go, orgRow in orgadmin.go); these wrap them with the
// per-session values a template needs.

type fleetData struct {
	Rows []fleetRow
	CSRF string
}

type deleteConfirmData struct {
	Name   string
	Online bool
	CSRF   string
}

// uiShellData is the chrome every page is rendered into.
type uiShellData struct {
	Title   string
	CSRF    string
	Email   string
	Subject string
	Notice  string
	// Public drops the operator navigation, for pages served to someone who is
	// not signed in — the enrollment page. Rendering a Fleet/Orgs nav there would
	// both advertise an admin surface and offer links that only bounce to a
	// sign-in that visitor cannot complete.
	Public bool
	// Version is the control plane's own version, rendered next to the signed-in
	// operator. It is set only for a page rendered for a live session: the
	// enrollment page is anonymous, and so are the sign-in message pages (which
	// render through this same shell with Public false), and neither has any
	// reason to tell a visitor which build to look up advisories for.
	Version string
	// Content is pre-rendered markup. See shellTemplate's comment: it is the
	// output of an html/template execution, which is why it may be trusted.
	Content template.HTML
}

const shellSource = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Title}}</title>
<script src="/static/htmx.min.js" defer></script>
<script src="/static/app.js" defer></script>
<style>` + uiBaseCSS + `</style>
</head><body hx-headers='{"X-CSRF-Token":"{{.CSRF}}"}'>
{{if not .Public}}<nav>
  <a href="/ui" {{if eq .Title "Fleet"}}aria-current="page"{{end}}>Fleet</a>
  <a href="/ui/orgs" {{if eq .Title "Orgs"}}aria-current="page"{{end}}>Orgs</a>
  {{if .CSRF}}
  <span class="who">{{if .Email}}{{.Email}}{{else}}{{.Subject}}{{end}}
    <form class="inline" method="post" action="/ui/logout">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <button type="submit">Sign out</button>
    </form>
  </span>
  {{end}}
  {{/* Deliberately a sibling of the CSRF block above, not a child of it, so the
       session check in renderPage is the single gate that withholds this.
       Nesting it inside that block would look right and be wrong: a second,
       implicit gate would hide the first from any test, so a later refactor
       could move this span and leak the version with the tests still green. */}}
  {{if .Version}}<span class="muted" title="the control plane build managing this fleet">mach-server {{.Version}}</span>{{end}}
</nav>{{end}}
{{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}
{{.Content}}
</body></html>`

// shellTemplate is the page chrome. Content is inserted as template.HTML, which
// is safe here for one reason: it is always the output of executing another
// html/template in renderPage, never a caller-supplied string. It is the
// composition mechanism, not an escaping bypass.
var shellTemplate = template.Must(template.New("shell").Parse(shellSource))

// fleetInnerSource is the polled region: the table (or the empty-state note),
// and nothing else. It is a separate define from the block that contains it
// because the two live in different swap targets — see fleetSource.
//
// It always renders an element with id="fleet-table", including when there are
// no machines. That is not cosmetic: the poll swaps into #fleet-table by id, and
// a response that omitted the id would leave every later poll with nothing to
// target, so the table would never come back once the fleet emptied.
const fleetInnerSource = `{{define "fleettable"}}
<div id="fleet-table">
{{if not .Rows}}
  <p class="muted">No machines enrolled yet. <a href="/">Enrollment page</a></p>
{{else}}
  <table>
  <thead><tr>
    <th>Machine</th><th>State</th><th>Platform</th><th>Agent</th><th>Actions</th>
  </tr></thead>
  <tbody>
  {{range .Rows}}
    <tr id="m-{{.Name}}">
      <td><code>{{.Name}}</code><div class="muted">{{.Hostname}}</div></td>
      <td>
        {{if .Revoked}}<span class="badge revoked">revoked</span>
        {{else if .Blocked}}<span class="badge blocked">blocked</span>{{end}}
        {{if .Temporary}}<span class="badge pinned">temporary</span>{{end}}
        {{if .Online}}<span class="badge online">online</span>
        {{else}}<span class="badge offline">offline</span>{{end}}
      </td>
      <td class="muted">{{.OS}}/{{.Arch}}</td>
      <td class="muted">{{.AgentVer}}{{if .AgentSkew}} <span class="badge" title="this agent reports a different version than this control plane">differs</span>{{end}}</td>
      <td>
        <div class="row-actions">
        {{if not .Revoked}}
          {{if .Blocked}}
          <form class="inline" method="post" action="/ui/unblock" hx-post="/ui/unblock" hx-target="#fleet" hx-swap="outerHTML">
            <input type="hidden" name="machine" value="{{.Name}}">
            <input type="hidden" name="csrf" value="{{$.CSRF}}">
            <button type="submit">Unblock</button>
          </form>
          {{else}}
          <form class="inline" method="post" action="/ui/block" hx-post="/ui/block" hx-target="#fleet" hx-swap="outerHTML">
            <input type="hidden" name="machine" value="{{.Name}}">
            <input type="hidden" name="csrf" value="{{$.CSRF}}">
            <button type="submit">Block</button>
          </form>
          {{end}}
          <form class="inline" method="post" action="/ui/revoke" hx-post="/ui/revoke" hx-target="#fleet" hx-swap="outerHTML"
                hx-confirm="Revoke {{.Name}}? Its agent is told to retire and its key stops working. The machine can come back by enrolling again under this same name — or use Delete to remove it and free the name for a different machine.">
            <input type="hidden" name="machine" value="{{.Name}}">
            <input type="hidden" name="csrf" value="{{$.CSRF}}">
            <button type="submit">Revoke</button>
          </form>
        {{end}}
        <form class="inline" method="post" action="/ui/delete" hx-post="/ui/delete" hx-target="#confirm" hx-swap="innerHTML">
          <input type="hidden" name="machine" value="{{.Name}}">
          <input type="hidden" name="csrf" value="{{$.CSRF}}">
          <button type="submit">Delete</button>
        </form>
        </div>
      </td>
    </tr>
  {{end}}
  </tbody></table>
{{end}}
</div>
{{end}}`

// fleetSource is the whole fleet block: the polled table inside a container that
// owns the polling, plus the panel the Delete confirmation is written into.
//
// The split is the fix for a real annoyance rather than a preference. Polling
// used to replace this whole container every five seconds, so a confirmation
// opened from a row — and the machine name half-typed into it — was thrown away
// by the next tick. The panel is now a sibling of the polled element, so a tick
// refreshes the table and leaves an open confirmation alone.
const fleetSource = `{{define "fleet"}}
<div id="fleet" hx-get="/ui/machines" hx-trigger="every 5s" hx-target="#fleet-table" hx-swap="outerHTML">
{{template "fleettable" .}}
<div id="confirm"></div>
</div>
{{end}}`

// deleteConfirmSource renders the typed-name confirmation into #confirm. It sits
// outside the polled region (see fleetSource), which is why it is a block of its
// own rather than a row replacing itself.
//
// A dialog would be a click through; the name is deliberately typed, because
// delete is the one action that removes the tombstone stopping a stolen key from
// re-enrolling, and it must not be reachable by a misclick on the wrong row.
//
// Submitting targets #fleet, whose response is the whole container again — a
// refreshed table with an empty panel. One target, so the table cannot be
// updated while the dialog stays on screen describing a machine that is gone.
// Cancel is a plain GET because dismissing a dialog changes nothing, and
// hx-params="none" keeps the form's fields (the session's CSRF token among them)
// out of a URL.
const deleteConfirmSource = `{{define "deleteconfirm"}}
<div class="panel">
  <p>This removes <code>{{.Name}}</code> and its key from the database. The name
  and the key are freed, so this host (or another with the same name) can enroll
  again. Audit rows are kept.</p>
  {{if .Online}}
  <p class="muted">The agent is connected and will be told to retire. An agent
  that is offline is not told, and will keep retrying until it is stopped on
  the host.</p>
  {{else}}
  <p class="muted">The agent is not connected, so it cannot be told to retire.
  It will keep retrying until it is stopped on the host.</p>
  {{end}}
  <form method="post" action="/ui/delete" hx-post="/ui/delete" hx-target="#fleet" hx-swap="outerHTML">
    <input type="hidden" name="machine" value="{{.Name}}">
    <input type="hidden" name="confirm" value="1">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label>Type <code>{{.Name}}</code> to confirm
      <input type="text" name="confirm_name" autocomplete="off" autofocus></label>
    <p class="row-actions">
      <button class="btn-primary" type="submit">Delete permanently</button>
      <button type="button" hx-get="/ui/confirm/clear" hx-target="#confirm"
              hx-swap="innerHTML" hx-params="none">Cancel</button>
    </p>
  </form>
</div>
{{end}}`

// confirmClearedSource is the empty panel Cancel swaps in.
const confirmClearedSource = `{{define "confirmcleared"}}{{end}}`

// orgsSource lists orgs and their machine counts. E2E is shown here read-only —
// the control for it lives on the org's own page, where the effective value and
// where it comes from are both visible, rather than as three buttons whose
// difference ("on", "off", "inherit") was not obvious from a list row.
const orgsSource = `{{define "orgs"}}
<div id="orgs">
<h2>Orgs</h2>
<p class="muted">Names are org-prefixed (<code>&lt;org&gt;-&lt;machine&gt;</code>).
Adding an org makes that prefix enrollable. An org that came from the environment
is pinned and cannot be removed here. E2E is a per-org setting, on the org's page.</p>
<table>
<thead><tr><th>Org</th><th>Machines</th><th>E2E</th><th>Actions</th></tr></thead>
<tbody>
{{range .Rows}}
  <tr>
    <td><a href="/ui/orgs/{{.Name}}"><code>{{.Name}}</code></a>
      {{if .Pinned}}<span class="badge pinned">pinned</span>{{end}}</td>
    <td>{{.Machines}}</td>
    <td>
      {{if .E2EEnabled}}<span class="badge online">on</span>{{else}}<span class="badge blocked">off</span>{{end}}
      <div class="muted">{{.E2ESource}}</div>
    </td>
    <td>
      <div class="row-actions">
      {{if not .Pinned}}
      <form class="inline" method="post" action="/ui/orgs/remove" hx-post="/ui/orgs/remove" hx-target="#orgs" hx-swap="outerHTML"
            hx-confirm="Remove org {{.Name}}? New machines can no longer enroll under this prefix. Existing machines keep working.">
        <input type="hidden" name="org" value="{{.Name}}">
        <input type="hidden" name="csrf" value="{{$.CSRF}}">
        <button type="submit">Remove</button>
      </form>
      {{end}}
      </div>
    </td>
  </tr>
{{end}}
</tbody></table>
<h3>Add an org</h3>
<form method="post" action="/ui/orgs/add" hx-post="/ui/orgs/add" hx-target="#orgs" hx-swap="outerHTML">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="text" name="org" placeholder="acme" autocomplete="off" required>
  <button type="submit">Add org</button>
</form>
<div class="muted">2-20 characters: letters, digits, hyphen.</div>
</div>
{{end}}`

// orgE2ESource is one org's E2E control, rendered on its own page and swapped in
// place by the two buttons.
//
// On/off is what an operator decides; "follow the fleet default" is a different
// thing — clearing an override so the org tracks whatever the fleet does — and
// it is offered only when an override exists to clear. Calling it "Inherit" in a
// list row, next to "E2E on" and "E2E off", made it look like a third value of
// the same setting rather than a statement about where the value comes from.
const orgE2ESource = `{{define "orge2e"}}
<div id="orge2e">
<h3>E2E</h3>
<p class="muted">End-to-end encrypted commands: this control plane relays them
without being able to read the command or its output. With E2E off, commands for
this org run in plaintext, where the control plane can read them and the
fleet-wide block list applies before anything is dispatched.</p>
{{if .E2EPinned}}<p class="notice">MACH_E2E pins every org to one value. A setting
saved here is kept, and takes effect again once that pin is removed.</p>{{end}}
{{if not .E2EOverridden}}<p class="muted">This org has no setting of its own and
follows the fleet default.</p>{{end}}
{{/* A div, not a p: the buttons live in their own forms, and a <form> start tag
     closes an open <p> in the HTML parser — the markup would not survive as
     written, and neither would the layout. */}}
<div class="e2e-row">
  <span class="seg">
    <form class="inline" method="post" action="/ui/orgs/e2e" hx-post="/ui/orgs/e2e" hx-target="#orge2e" hx-swap="outerHTML">
      <input type="hidden" name="org" value="{{.Org}}">
      <input type="hidden" name="view" value="member">
      <input type="hidden" name="mode" value="on">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <button type="submit" {{if .E2EOn}}class="active"{{end}}>On</button>
    </form>
    <form class="inline" method="post" action="/ui/orgs/e2e" hx-post="/ui/orgs/e2e" hx-target="#orge2e" hx-swap="outerHTML">
      <input type="hidden" name="org" value="{{.Org}}">
      <input type="hidden" name="view" value="member">
      <input type="hidden" name="mode" value="off">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <button type="submit" {{if not .E2EOn}}class="active"{{end}}>Off</button>
    </form>
  </span>
  {{if .E2EOverridden}}
  <form class="inline" method="post" action="/ui/orgs/e2e" hx-post="/ui/orgs/e2e" hx-target="#orge2e" hx-swap="outerHTML">
    <input type="hidden" name="org" value="{{.Org}}">
    <input type="hidden" name="view" value="member">
    <input type="hidden" name="mode" value="inherit">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <button type="submit">Follow the fleet default</button>
  </form>
  {{end}}
</div>
<p class="muted">Effective for <code>{{.Org}}</code>: <b>{{.E2EMode}}</b> — {{.E2ESource}}.</p>
</div>
{{end}}`

// memberSource is one org's membership view. Keys have no org column — scopes is
// a string — so membership is derived and the two groups are labelled to say so
// rather than implying keys belong to an org.
const memberSource = `{{define "orgmember"}}
<h2>Org <code>{{.Org}}</code></h2>
<p><a href="/ui/orgs">&larr; All orgs</a></p>
{{if .Pinned}}<p class="muted">This org comes from the environment
(<code>MACH_ORG</code>/<code>MACH_ORGS</code>), so it cannot be removed here.</p>{{end}}

{{template "orge2e" .}}

<h3>Machines ({{len .Machines}})</h3>
{{if not .Machines}}<p class="muted">None.</p>{{else}}
<table><thead><tr><th>Machine</th><th>State</th><th>Platform</th></tr></thead><tbody>
{{range .Machines}}
<tr><td><code>{{.Name}}</code><div class="muted">{{.Hostname}}</div></td>
<td>{{if .Revoked}}<span class="badge revoked">revoked</span>
{{else if .Blocked}}<span class="badge blocked">blocked</span>{{end}}
{{if .Online}}<span class="badge online">online</span>{{else}}<span class="badge offline">offline</span>{{end}}</td>
<td class="muted">{{.OS}}/{{.Arch}}</td></tr>
{{end}}
</tbody></table>
{{end}}

<h3>Keys scoped to this org's machines ({{len .ScopedKeys}})</h3>
{{if not .ScopedKeys}}<p class="muted">None.</p>{{else}}
<table><thead><tr><th>Key</th><th>Scopes</th><th>Created</th></tr></thead><tbody>
{{range .ScopedKeys}}<tr><td><code>{{.Name}}</code></td><td><code>{{.Scopes}}</code></td>
<td class="muted">{{.CreatedAt}}</td></tr>{{end}}
</tbody></table>
{{end}}

<h3>Fleet-wide keys ({{len .FleetKeys}})</h3>
<p class="muted">These are not scoped to an org. An <code>exec:*</code>,
<code>readonly</code> or <code>enroll</code> key reaches every org, which is why
they are listed separately rather than counted as members of this one.</p>
{{if not .FleetKeys}}<p class="muted">None.</p>{{else}}
<table><thead><tr><th>Key</th><th>Scopes</th><th>Created</th></tr></thead><tbody>
{{range .FleetKeys}}<tr><td><code>{{.Name}}</code></td><td><code>{{.Scopes}}</code></td>
<td class="muted">{{.CreatedAt}}</td></tr>{{end}}
</tbody></table>
{{end}}
{{end}}`

// loginFailedSource is shown when sign-in could not complete. The reason is a
// fixed string from the server, never the identity provider's error text.
const loginFailedSource = `{{define "loginfailed"}}
<h2>Sign-in unavailable</h2>
<p>{{.Reason}}</p>
<p class="muted">Nothing about this fleet was changed. Try again, and if it
persists check the control plane's log for the discovery error.</p>
{{end}}`

// uiTmpl is every UI markup define, in one set. It is one set rather than one
// per page because the pages now nest: the fleet page embeds the polled table,
// and one org's page embeds its E2E control, so a define has to be resolvable
// from the template that includes it.
var uiTmpl = template.Must(template.New("ui").Parse(
	fleetInnerSource + fleetSource + deleteConfirmSource + confirmClearedSource +
		orgsSource + orgE2ESource + memberSource + loginFailedSource))

// renderPage executes a content template and wraps it in the shared shell.
func (s *Server) renderPage(w http.ResponseWriter, status int, sess uiSession, notice, title string,
	tmpl *template.Template, define string, data any) {
	shell := uiShellData{
		Title: title, CSRF: sess.CSRF, Email: sess.Ident.Email,
		Subject: sess.Ident.Subject, Notice: notice,
	}
	// Only a page rendered for a verified identity carries the version — and the
	// test is the session, not Public: renderSignInMessage renders this same
	// shell with Public false and an empty uiSession (a callback that arrived
	// without its state, an unreachable provider), and that visitor is anonymous.
	// oidcauth refuses an identity with no subject, so a non-empty one is proof
	// of a completed sign-in.
	if sess.Ident.Subject != "" {
		shell.Version = version.Version
	}
	s.renderIntoShell(w, status, shell, tmpl, define, data)
}

// renderPublicPage renders through the same shell with no operator chrome, for
// pages served to someone who cannot sign in (the enrollment page).
func (s *Server) renderPublicPage(w http.ResponseWriter, status int, title string,
	tmpl *template.Template, define string, data any) {
	s.renderIntoShell(w, status, uiShellData{Title: title, Public: true}, tmpl, define, data)
}

// renderIntoShell is the composition step.
//
// It runs the content template into a buffer first, so a template error is caught
// before any of the response has been written — the shell is only started once
// there is something to put in it.
func (s *Server) renderIntoShell(w http.ResponseWriter, status int, shell uiShellData,
	tmpl *template.Template, define string, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, define, data); err != nil {
		s.logf("ui: template %s: %v", define, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	// Safe by construction: this is the output of an html/template execution, so
	// every interpolated value in it is already escaped. It is the composition
	// mechanism, not an escaping bypass.
	shell.Content = template.HTML(buf.String()) //nolint:gosec
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = shellTemplate.Execute(w, shell)
}

// renderFragment writes a content template with no shell, for an htmx swap.
//
// These responses carry the same security headers as full pages: a fragment is
// still a response the browser processes, and skipping the headers on it would
// leave a hole in exactly the requests that mutate state.
func (s *Server) renderFragment(w http.ResponseWriter, sess uiSession, tmpl *template.Template, define string, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, define, data); err != nil {
		s.logf("ui: template %s: %v", define, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	_, _ = w.Write(buf.Bytes())
}
