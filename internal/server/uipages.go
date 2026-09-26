package server

import "github.com/TevaServices/mach/internal/store"

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
//
// The styling is NOT here. It is an authored stylesheet at static/ui.css, embedded
// and served as a cache-busted asset to the pages that may load one — and inlined
// from those same bytes into the pair page, which may not (see assets.go and
// pairpages.go). It used to be a const in this file, shared by string
// concatenation; one file with two delivery mechanisms is what keeps the three
// pages from drifting apart again.

import (
	"bytes"
	"html/template"
	"net/http"

	"github.com/TevaServices/mach/internal/version"
)

// View models. The row types live next to the code that assembles them
// (fleetRow in machineadmin.go, orgRow in orgadmin.go); these wrap them with the
// per-session values a template needs.

type fleetData struct {
	Rows []fleetRow
	CSRF string
	// Approvals is the pending-approval queue the page's panel shows. It rides
	// the same data struct because the panel is embedded in the fleet page's
	// template; the polled panel fragment carries its own approvalsData.
	Approvals []store.CommandApproval
	// Notice is the fixed sentence for the action that just happened. It is
	// rendered out of band from an action's response (see noticeOOBSource) and
	// inline by the shell on the no-JS path, from the same uiNotices map — so the
	// two paths cannot say different things.
	Notice string
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
	// AssetVersion is the ?v= on every /static/ URL below. It is set by
	// renderIntoShell rather than by each caller, because that function is the one
	// place the shell is executed: a caller that forgot it would ship a page whose
	// assets are served under a stale immutable cache, and the symptom would be
	// old behaviour with nothing in any log. Callers leave it empty.
	AssetVersion string
	// Page identifies which page this is, for the nav's aria-current. It is set by
	// renderIntoShell from the template define name, so it cannot drift from what
	// is actually being rendered — the nav used to key the highlight off Title,
	// which meant renaming a page's heading silently stopped highlighting its nav
	// link, and the two are genuinely different strings (an org's page is titled
	// "Org acme" but is the Orgs page).
	Page string
	// Content is pre-rendered markup. See shellTemplate's comment: it is the
	// output of an html/template execution, which is why it may be trusted.
	Content template.HTML
}

// shellSource is the page chrome.
//
// The stylesheet is a linked, cache-busted asset rather than an inline <style>
// block. That is what lets the shared styling be one authored file (static/ui.css)
// instead of a string const three templates concatenate — and the ?v= is not
// optional: handleUIStatic serves these with `max-age=31536000, immutable`, so
// without a digest in the URL a browser keeps a stale ui.css or app.js for a year
// and the pages go on running last deploy's behaviour.
//
// The pair page deliberately does NOT do this. It is reached from a QR code by an
// anonymous visitor and keeps `default-src 'none'`, under which a linked
// stylesheet is blocked outright; it inlines the same bytes instead. See
// pairpages.go.
const shellSource = `<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
{{/* htmx otherwise injects an inline <style> block for its htmx-indicator
     class, which needs style-src 'unsafe-inline'. Nothing here uses
     hx-indicator, so turning it off lets the CSP drop that relaxation — and a
     declarative meta is what makes it independent of script ordering: this is
     read when htmx initialises, whereas a config set in app.js would depend on
     both scripts being deferred in the right order. */}}
<meta name="htmx-config" content='{"includeIndicatorStyles":false}'>
<title>{{.Title}}</title>
<link rel="stylesheet" href="/static/ui.css?v={{.AssetVersion}}">
<script src="/static/htmx.min.js?v={{.AssetVersion}}" defer></script>
<script src="/static/app.js?v={{.AssetVersion}}" defer></script>
</head><body hx-headers='{"X-CSRF-Token":"{{.CSRF}}"}'>
{{if not .Public}}<a class="skip-link" href="#main">Skip to content</a>
<header class="site-header"><nav aria-label="Main">
  <span class="nav-links">
    <a href="/ui" {{if eq .Page "fleet"}}aria-current="page"{{end}}>Fleet</a>
    <a href="/ui/orgs" {{if or (eq .Page "orgs") (eq .Page "orgmember")}}aria-current="page"{{end}}>Orgs</a>
  </span>
  {{/* .nav-right is one group pushed to the end of the row. The reading order
       inside it is build identity then account, so the account actions are
       rightmost — which is what the old markup got wrong: .who carried
       margin-left:auto and the version span was its following sibling, so the
       rightmost thing on the page was "mach-server <version>" and the email and
       Sign out sat to its left. */}}
  <span class="nav-right">
  {{/* Deliberately a sibling of the CSRF block below, not a child of it, so the
       session check in renderPage is the single gate that withholds this.
       Nesting it inside that block would look right and be wrong: a second,
       implicit gate would hide the first from any test, so a later refactor
       could move this span and leak the version with the tests still green.
       The .nav-right wrapper is presentational and does not change that: the
       two {{if}}s stay siblings. */}}
  {{if .Version}}<span class="muted" title="the control plane build managing this fleet">mach-server {{.Version}}</span>{{end}}
  {{if .CSRF}}
  <span class="who">{{if .Email}}{{.Email}}{{else}}{{.Subject}}{{end}}
    <form class="inline" method="post" action="/ui/logout">
      <input type="hidden" name="csrf" value="{{.CSRF}}">
      <button type="submit">Sign out</button>
    </form>
  </span>
  {{end}}
  </span>
</nav></header>{{end}}
<main id="main">
<h1>{{.Title}}</h1>
{{/* Two live regions, split by urgency rather than by looks. A refusal is the
     operator's own action coming back and should interrupt, so it is role="alert"
     (assertive). A confirmation arriving a beat after a click should not, so it is
     role="status" (polite). Both are populated out of band by the fragments an
     action returns; keeping them here rather than in the swapped content is what
     makes them survive the swap.

     The polled fleet table is deliberately NOT a live region. It is replaced every
     five seconds, and a polite region containing it would re-announce the whole
     fleet forever — which is worse than silence for anyone using a screen reader.
     Announcements are for changes the operator caused. */}}
<div id="ui-error" role="alert"></div>
<div id="ui-notice" role="status">{{if .Notice}}<p class="notice">{{.Notice}}</p>{{end}}</div>
{{.Content}}
</main>
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
{{/* aria-live="off" is the default value, and it is written out to say the quiet
     part loudly: this element is replaced every five seconds, so it must never
     become a live region — a polite one containing it would re-announce the whole
     fleet forever, which is worse than silence for anyone using a screen reader.
     The regions that do announce are #ui-error and #ui-notice in the shell, and
     they announce changes the operator caused. */}}
<div id="fleet-table" aria-live="off">
{{if not .Rows}}
  <p class="muted">No machines enrolled yet. <a href="/">Enrollment page</a></p>
{{else}}
  <div class="table-scroll" role="region" aria-label="Fleet" tabindex="0">
  <table>
  <caption class="sr-only">Enrolled machines, their state, and the actions available for each</caption>
  <thead><tr>
    <th scope="col">Machine</th><th scope="col">State</th><th scope="col">Platform</th><th scope="col">Agent</th><th scope="col">Actions</th>
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
      <td>{{.OS}}/{{.Arch}}</td>
      <td>{{.AgentVer}}{{if .AgentSkew}} <span class="badge" title="this agent reports a different version than this control plane">differs</span>{{end}}</td>
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
            <button type="submit" class="danger">Revoke</button>
          </form>
        {{end}}
        <form class="inline" method="post" action="/ui/delete" hx-post="/ui/delete" hx-target="#confirm" hx-swap="innerHTML">
          <input type="hidden" name="machine" value="{{.Name}}">
          <input type="hidden" name="csrf" value="{{$.CSRF}}">
          <button type="submit" class="danger">Delete</button>
        </form>
        </div>
      </td>
    </tr>
  {{end}}
  </tbody></table>
  </div>
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
<div id="approvals">
<div id="approvals-panel" hx-get="/ui/approvals" hx-trigger="every 5s" hx-target="#approvals-panel" hx-swap="outerHTML">
{{with .Approvals}}{{template "approvals" .}}{{end}}
</div>
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
  <p>This removes <code>{{.Name}}</code> and its key. The name is freed for
  re-enrollment; audit rows are kept.</p>
  {{if .Online}}
  <p class="muted">The agent is connected and will be told to retire.</p>
  {{else}}
  <p class="muted">The agent is offline, so it cannot be told — it will keep
  retrying until stopped on the host.</p>
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

// deleteConfirmPageSource is the same confirmation as a page, for a form post
// with scripting off.
//
// It is a near-copy of deleteconfirmSource on purpose rather than a shared
// define: this one must carry no hx-* attribute at all, and Cancel must be a real
// link. Sharing would mean branching on "is this htmx" inside the template, which
// is exactly the kind of conditional that ends up wrong on one of the two paths.
// The typed-name gate, which is the part that must not drift, is asserted for
// both by TestUIDeleteRequiresTypedName.
const deleteConfirmPageSource = `{{define "deleteconfirmpage"}}
<div class="panel">
  <p>This removes <code>{{.Name}}</code> and its key. The name is freed for
  re-enrollment; audit rows are kept.</p>
  {{if .Online}}
  <p class="muted">The agent is connected and will be told to retire.</p>
  {{else}}
  <p class="muted">The agent is offline, so it cannot be told — it will keep
  retrying until stopped on the host.</p>
  {{end}}
  <form method="post" action="/ui/delete">
    <input type="hidden" name="machine" value="{{.Name}}">
    <input type="hidden" name="confirm" value="1">
    <input type="hidden" name="csrf" value="{{.CSRF}}">
    <label>Type <code>{{.Name}}</code> to confirm
      <input type="text" name="confirm_name" autocomplete="off" autofocus></label>
    <p class="row-actions">
      <button class="btn-primary" type="submit">Delete permanently</button>
      <a class="btn" href="/ui">Cancel</a>
    </p>
  </form>
</div>
{{end}}`

// ---- refusals ----
//
// A refusal used to be a JSON body with a 4xx status, and htmx does not swap
// non-2xx responses — so every refused action in the browser was a silent no-op.
// Adding a duplicate org, removing an org that still has machines, and posting a
// bad E2E mode all did *nothing visible at all*, on pages whose whole point is
// that an operator can see what happened. The sentences were well written and
// never reached a human.
//
// The fix is two-sided: the server names a destination for the refusal (HX-Retarget
// in uiFail), and app.js opts in to swapping responses that carry one. Neither
// half does anything without the other, which is why they are commented together.

// uiErrorSource is the refusal as a fragment, for htmx to swap into #ui-error.
//
// No role="alert" here: the live region is the persistent #ui-error element in
// the shell, and a live region has to be in the DOM before its content changes
// for the change to be announced. Putting the role on the swapped-in node would
// create the region and fill it in the same breath, which announces nothing.
// approvalsSource is the pending-approvals panel on the fleet page. It sits
// OUTSIDE the polled #fleet container (see fleetSource): the panel polls on its
// own five-second tick into its own slot, so a table tick can never throw away
// an approval decision mid-click, and an approval never fights the table's
// polling for the same element.
//
// Approve posts to /ui/approve with the row's id; Deny the same. Both re-render
// through approvalsaction, whose response replaces the whole panel and carries
// the notice out of band — the same shape every other fleet action uses.
const approvalsSource = `{{define "approvals"}}
<div class="table-scroll" role="region" aria-label="Pending command approvals" tabindex="0">
{{if not .Approvals}}
  <p class="muted">No commands are waiting for approval.</p>
{{else}}
  <table>
  <caption class="sr-only">Commands the fleet-wide policy refused, waiting for a decision</caption>
  <thead><tr>
    <th scope="col">Machine</th><th scope="col">Command</th><th scope="col">Requested</th><th scope="col">Actions</th>
  </tr></thead>
  <tbody>
  {{range .Approvals}}
    <tr>
      <td><code>{{.Machine}}</code></td>
      <td><code>{{.Command}}</code></td>
      <td class="muted">{{.CreatedAt}}</td>
      <td>
        <div class="row-actions">
        <form class="inline" method="post" action="/ui/approve" hx-post="/ui/approve" hx-target="#approvals" hx-swap="outerHTML">
          <input type="hidden" name="id" value="{{.ID}}">
          <input type="hidden" name="csrf" value="{{$.CSRF}}">
          <button type="submit">Approve once</button>
        </form>
        <form class="inline" method="post" action="/ui/deny" hx-post="/ui/deny" hx-target="#approvals" hx-swap="outerHTML">
          <input type="hidden" name="id" value="{{.ID}}">
          <input type="hidden" name="csrf" value="{{$.CSRF}}">
          <button type="submit" class="danger">Deny</button>
        </form>
        </div>
      </td>
    </tr>
  {{end}}
  </tbody></table>
{{end}}
  </div>
{{end}}`

// approvalsActionSource is the response to an approve/deny: the refreshed
// panel plus the notice, out of band — the same shape as fleetaction.
const approvalsActionSource = `{{define "approvalsaction"}}{{template "noticeoob" .}}{{template "approvals" .}}{{end}}`

const uiErrorSource = `{{define "uierror"}}<p class="error">{{.Msg}}</p>{{end}}`

// uiErrorPageSource is the same refusal as a page body, for a caller that cannot
// consume a fragment — a form post with scripting off, which used to be answered
// with a raw JSON object in the browser window.
const uiErrorPageSource = `{{define "uierrorpage"}}
<p class="error">{{.Msg}}</p>
<p class="muted">Nothing on this control plane was changed by that request.</p>
<p><a href="/ui">Back to the fleet</a></p>
{{end}}`

// ---- notices ----
//
// The mirror image of the refusal problem: uiNotices holds eight well-written
// sentences, and they were reachable only through the ?n= redirect, which only a
// scripting-off browser follows. With htmx on — the normal case — a successful
// block, revoke, delete or org-add produced no confirmation whatsoever.

// noticeOOBSource is the out-of-band notice every action response carries.
//
// It is a top-level element rather than something nested inside the swapped
// content, so it does not depend on htmx's allowNestedOobSwaps default. It swaps
// *into* #ui-notice rather than replacing it: a live region must persist across
// the change for the change to be announced.
const noticeOOBSource = `{{define "noticeoob"}}{{if .Notice}}<div hx-swap-oob="innerHTML:#ui-notice"><p class="notice">{{.Notice}}</p></div>{{end}}{{end}}`

// The action wrappers. Each is the notice followed by the region the action
// normally returns, and each exists as its own define because the page render
// must NOT carry the out-of-band div: a normal page load has no htmx swap to
// process it, so it would sit in the document as a stray element duplicating the
// notice the shell already rendered from .Notice.
const fleetActionSource = `{{define "fleetaction"}}{{template "noticeoob" .}}{{template "fleet" .}}{{end}}`

const orgsActionSource = `{{define "orgsaction"}}{{template "noticeoob" .}}{{template "orgs" .}}{{end}}`

const orgE2EActionSource = `{{define "orge2eaction"}}{{template "noticeoob" .}}{{template "orge2e" .}}{{end}}`

// orgsSource lists orgs and their machine counts. E2E is shown here read-only —
// the control for it lives on the org's own page, where the effective value and
// where it comes from are both visible, rather than as three buttons whose
// difference ("on", "off", "inherit") was not obvious from a list row.
//
// There is deliberately no Actions column. The one action an org row ever
// offered was Remove, and removal is an org-level decision, not a row-level
// reflex: it lives on the org's page (memberSource) next to what removal
// actually affects, and behind one navigation click rather than sitting in
// every row of the list.
const orgsSource = `{{define "orgs"}}
<div id="orgs">
<p class="muted">Machine names are <code>&lt;org&gt;-&lt;machine&gt;</code>.
An org that came from the environment is pinned. Settings and removal are on
each org's page.</p>
<div class="table-scroll" role="region" aria-label="Orgs" tabindex="0">
<table>
<caption class="sr-only">Configured org prefixes, their machine counts, and their sealed-exec setting</caption>
<thead><tr><th scope="col">Org</th><th scope="col">Machines</th><th scope="col">E2E</th></tr></thead>
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
  </tr>
{{end}}
</tbody></table>
</div>
<h2>Add an org</h2>
<form class="add-org" method="post" action="/ui/orgs/add" hx-post="/ui/orgs/add" hx-target="#orgs" hx-swap="outerHTML">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <input type="text" name="org" placeholder="acme" autocomplete="off" required aria-label="Org name">
  <button type="submit">Add org</button>
</form>
<p class="muted">2-20 characters: letters, digits, hyphen.</p>
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
<h2>Sealed exec (E2E)</h2>
<p class="muted">With E2E on, one-shot commands are end-to-end encrypted: the
control plane relays them without reading them. With it off, commands run in
plaintext and the fleet-wide block list applies before dispatch.</p>
{{if .E2EPinned}}<p class="notice">MACH_E2E pins every org to one value. A setting
saved here is kept, and takes effect again once that pin is removed.</p>{{end}}
{{if not .E2EOverridden}}<p class="muted">This org follows the fleet default.</p>{{end}}
{{/* ONE form with three named submit buttons, not three forms with one hidden
     mode field each. The server contract is unchanged — it reads
     PostFormValue("mode"), and a submit button contributes its own name/value —
     but there is now one copy of org/view/csrf instead of three, which is three
     chances for one of them to be edited and the others missed.

     aria-pressed is the accessible state and .active is no longer written by the
     template at all: the stylesheet keys the pressed look off [aria-pressed=true],
     so the visual state cannot disagree with the announced one. A div, not a p:
     a <form> start tag closes an open <p> in the HTML parser, and the markup
     would not survive as written. */}}
<div class="e2e-row">
<form method="post" action="/ui/orgs/e2e" hx-post="/ui/orgs/e2e" hx-target="#orge2e" hx-swap="outerHTML">
  <input type="hidden" name="org" value="{{.Org}}">
  <input type="hidden" name="view" value="member">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <span class="seg" role="group" aria-label="Sealed exec for this org">
    <button type="submit" name="mode" value="on" aria-pressed="{{if .E2EOn}}true{{else}}false{{end}}">On</button>
    <button type="submit" name="mode" value="off" aria-pressed="{{if .E2EOn}}false{{else}}true{{end}}">Off</button>
  </span>
  {{if .E2EOverridden}}
  <button type="submit" name="mode" value="inherit">Follow the fleet default</button>
  {{end}}
</form>
</div>
<p class="muted">Effective for <code>{{.Org}}</code>: <b>{{.E2EMode}}</b> — {{.E2ESource}}.</p>
</div>
{{end}}`

// memberSource is one org's membership view. Keys have no org column — scopes is
// a string — so membership is derived and the two groups are labelled to say so
// rather than implying keys belong to an org.
// It carries no page heading: the shell renders one from .Title ("Org acme"),
// which is also a better h1 than the old `<h2>Org <code>acme</code></h2>` — a
// heading whose text is split across an element reads as two fragments to a
// screen reader listing the page's headings.
//
// The Remove action lives here, not in the org list's rows. It is a plain form
// post on purpose: the htmx branch of /ui/orgs/remove answers with the orgs
// LIST fragment (for the #orgs target the list page has), and this page has no
// such target — a successful removal should simply navigate to /ui/orgs, which
// is exactly what the non-htmx redirect does.
const memberSource = `{{define "orgmember"}}
<p><a href="/ui/orgs">&larr; All orgs</a></p>
{{if .Pinned}}<p class="muted">This org comes from the environment
(<code>MACH_ORG</code>/<code>MACH_ORGS</code>), so it cannot be removed.</p>{{end}}

{{template "orge2e" .}}

<h2>Machines ({{len .Machines}})</h2>
{{if not .Machines}}<p class="muted">None.</p>{{else}}
<div class="table-scroll" role="region" aria-label="Machines in this org" tabindex="0">
<table>
<caption class="sr-only">Machines enrolled under this org's prefix</caption>
<thead><tr><th scope="col">Machine</th><th scope="col">State</th><th scope="col">Platform</th></tr></thead><tbody>
{{range .Machines}}
<tr><td><code>{{.Name}}</code><div class="muted">{{.Hostname}}</div></td>
<td>{{if .Revoked}}<span class="badge revoked">revoked</span>
{{else if .Blocked}}<span class="badge blocked">blocked</span>{{end}}
{{if .Online}}<span class="badge online">online</span>{{else}}<span class="badge offline">offline</span>{{end}}</td>
<td>{{.OS}}/{{.Arch}}</td></tr>
{{end}}
</tbody></table>
</div>
{{end}}

<h2>Keys scoped to this org's machines ({{len .ScopedKeys}})</h2>
{{if not .ScopedKeys}}<p class="muted">None.</p>{{else}}
<div class="table-scroll" role="region" aria-label="Keys scoped to this org" tabindex="0">
<table>
<caption class="sr-only">API keys whose exec allowlist names a machine in this org</caption>
<thead><tr><th scope="col">Key</th><th scope="col">Scopes</th><th scope="col">Created</th></tr></thead><tbody>
{{range .ScopedKeys}}<tr><td><code>{{.Name}}</code></td><td><code>{{.Scopes}}</code></td>
<td>{{.CreatedAt}}</td></tr>{{end}}
</tbody></table>
</div>
{{end}}

<h2>Fleet-wide keys ({{len .FleetKeys}})</h2>
<p class="muted">Not scoped to an org — an <code>exec:*</code>, <code>readonly</code>
or <code>enroll</code> key reaches every org, so they are listed separately.</p>
{{if not .FleetKeys}}<p class="muted">None.</p>{{else}}
<div class="table-scroll" role="region" aria-label="Fleet-wide keys" tabindex="0">
<table>
<caption class="sr-only">API keys that reach every org</caption>
<thead><tr><th scope="col">Key</th><th scope="col">Scopes</th><th scope="col">Created</th></tr></thead><tbody>
{{range .FleetKeys}}<tr><td><code>{{.Name}}</code></td><td><code>{{.Scopes}}</code></td>
<td>{{.CreatedAt}}</td></tr>{{end}}
</tbody></table>
</div>
{{end}}

{{if not .Pinned}}
<h2>Remove this org</h2>
<p class="muted">New machines can no longer enroll under the
<code>{{.Org}}</code>- prefix; existing machines keep working. An org that still
has machines cannot be removed.</p>
<form method="post" action="/ui/orgs/remove">
  <input type="hidden" name="org" value="{{.Org}}">
  <input type="hidden" name="csrf" value="{{.CSRF}}">
  <button type="submit" class="danger">Remove org</button>
</form>
{{end}}
{{end}}`

// loginFailedSource is shown when sign-in could not complete. The reason is a
// fixed string from the server, never the identity provider's error text.
//
// It carries no heading of its own: the shell renders one from .Title, which is
// the same string the <title> gets. It used to hardcode <h2>Sign-in unavailable</h2>
// while the <title> said something else entirely ("Sign-in refused", "Signed
// out"), so the tab and the page disagreed about what had happened.
const loginFailedSource = `{{define "loginfailed"}}
<p>{{.Reason}}</p>
<p class="muted">Nothing about this fleet was changed. Try again, and if it
persists check the control plane's log for the discovery error.</p>
{{end}}`

// uiTmpl is every UI markup define, in one set. It is one set rather than one
// per page because the pages now nest: the fleet page embeds the polled table,
// and one org's page embeds its E2E control, so a define has to be resolvable
// from the template that includes it.
var uiTmpl = template.Must(template.New("ui").Parse(
	fleetInnerSource + fleetSource + fleetActionSource + deleteConfirmSource + deleteConfirmPageSource + confirmClearedSource +
		approvalsSource + approvalsActionSource +
		orgsSource + orgsActionSource + orgE2ESource + orgE2EActionSource +
		memberSource + loginFailedSource + uiErrorSource + uiErrorPageSource + noticeOOBSource))

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
	// Set here rather than by callers: this is the only place the shell is
	// executed, so no page can ship without the cache-busting digest.
	shell.AssetVersion = assetVersion
	// The define name IS the page's identity, so deriving it here means the nav
	// highlight cannot disagree with what was rendered.
	shell.Page = define
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
	s.renderFragmentStatus(w, sess, http.StatusOK, tmpl, define, data)
}

// renderFragmentStatus is renderFragment with a status code, for a refusal that
// is delivered as markup rather than as JSON.
//
// The status has to be written before the body, which is the whole reason this
// is a separate function: the original wrote its headers after the body and so
// could only ever answer 200.
func (s *Server) renderFragmentStatus(w http.ResponseWriter, sess uiSession, status int,
	tmpl *template.Template, define string, data any) {
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, define, data); err != nil {
		s.logf("ui: template %s: %v", define, err)
		http.Error(w, "template error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write(buf.Bytes())
}
