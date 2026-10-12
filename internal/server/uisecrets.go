package server

// Secrets in the web UI: the registry's names, a browser-sealed push, and the
// org-wide delete fan-out.
//
// The page never sees and never sends a VALUE. The push form's value input has
// no name, so no request from the page ever carries plaintext — the browser
// seals the value to the machine's E2E key (cmd/uiseal, the wasm build of the
// one seal implementation) and only the sealed blob reaches this server. The
// handler refuses a request that arrives with a plaintext value field, so a
// scripting-unavailable browser cannot even accidentally ship a value here:
// the CLI (`mach secrets push`) is the no-JS path, and the server-side core is
// shared with it (relaySealedSecretPush) because a second copy of the E2E/
// block/audit guards is how two surfaces drift.
//
// Delete is names-only at the wire too, which is why it is NOT gated on the
// org's E2E setting: nothing sensitive crosses, while a value does not even
// exist for the registry delete itself.

import (
	"encoding/json"
	"net/http"
	"strings"
)

// uiSecretRow is one registry row as the page renders it. There is nothing
// secret in it by construction — the row type has no value field, which is
// the strongest form of that statement the page can make.
type uiSecretRow struct {
	Org        string
	Name       string
	CreatedAt  string
	CreatedBy  string
	LastSeenAt string
}

// machineSealInfo is what the browser needs to seal a value to one machine.
// PubE2E is a PUBLIC key — the same fact /e2epub hands a console — and like
// /e2epub it is advertised only when the org's E2E setting is on; with it off
// the entry carries the refusal reason instead, and the browser says so
// rather than believing sealing worked.
type machineSealInfo struct {
	Org    string `json:"org"`
	PubE2E string `json:"pub_e2e,omitempty"`
	Reason string `json:"reason,omitempty"`
	Online bool   `json:"online"`
}

type secretsData struct {
	Rows []uiSecretRow
	// SealJSON is the machine → seal-info map rendered for the browser's
	// secrets.js and the wasm to read (html/template escapes the attribute).
	// Only machines of orgs this session may act on appear here.
	SealJSON string
	Machines []string
	// Super shows the org column and every org's rows.
	Super bool
	CSRF  string
	// SealAssetVersion is the asset digest for the wasm URL, filled from the
	// same package value the shell uses for its scripts: a browser caching the
	// wasm for a year must cache the bytes it fetched with this exact URL.
	SealAssetVersion string
	Notice           string
}

// handleUISecrets renders the secrets page: every registry row this session's
// memberships can see, the machines it can act on with their E2E posture, and
// the add/update + delete controls. Any signed-in member may READ: secrets are
// names only, and hiding the page from viewers would say nothing about values.
func (s *Server) handleUISecrets(w http.ResponseWriter, r *http.Request, sess uiSession) {
	// This page is the one that compiles WebAssembly (the browser-side seal,
	// cmd/uiseal): its response relaxes script-src with 'wasm-unsafe-eval',
	// which the uiHeaders default did not carry. Set here rather than in the
	// uiGet wrapper so every other page keeps the stricter policy.
	w.Header().Set("Content-Security-Policy", uiCSPWasm)
	rows, err := s.secretRowsFor(sess)
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	info, machines, err := s.sealInfoFor(sess)
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	data := secretsData{
		Rows:             rows,
		SealJSON:         jsonForPage(info),
		Machines:         machines,
		Super:            sess.isSuper(),
		CSRF:             sess.CSRF,
		SealAssetVersion: assetVersion,
		Notice:           uiNoticeText(r.URL.Query().Get("n")),
	}
	s.renderPage(w, http.StatusOK, sess, data.Notice, "Secrets", uiTmpl, "secrets", data)
}

// secretRowsFor is the registry listing a session may see: a superadmin sees
// every org's rows (with the org column), everyone else sees only the orgs
// they are a member of — the same filter fleetRowsFor applies to machines,
// because a tenant boundary that holds for machines must hold for the
// metadata about them too.
func (s *Server) secretRowsFor(sess uiSession) ([]uiSecretRow, error) {
	all, err := s.st.ListSecrets("")
	if err != nil {
		return nil, err
	}
	if sess.isSuper() {
		out := make([]uiSecretRow, 0, len(all))
		for _, si := range all {
			out = append(out, uiSecretRow(si))
		}
		return out, nil
	}
	member := map[string]bool{}
	for _, o := range sess.memberOrgs() {
		member[o] = true
	}
	out := make([]uiSecretRow, 0, len(all))
	for _, si := range all {
		if !member[si.Org] {
			continue
		}
		out = append(out, uiSecretRow{Org: si.Org, Name: si.Name, CreatedAt: si.CreatedAt, CreatedBy: si.CreatedBy, LastSeenAt: si.LastSeenAt})
	}
	return out, nil
}

// sealInfoFor builds the page's machine → seal-info map (and the datalist
// names) from the machines this session may act on. The E2E posture comes
// from the same resolution the console API answers /e2epub with, so the page
// cannot advertise a key for an org that has sealing off.
func (s *Server) sealInfoFor(sess uiSession) (map[string]machineSealInfo, []string, error) {
	machines, err := s.st.ListMachines()
	if err != nil {
		return nil, nil, err
	}
	mayAct := map[string]bool{}
	if sess.isSuper() {
		for i := range machines {
			mayAct[machines[i].Org] = true
		}
	} else {
		for _, o := range sess.memberOrgs() {
			mayAct[o] = true
		}
	}
	info := make(map[string]machineSealInfo)
	names := make([]string, 0, len(machines))
	online := s.br.OnlineNames()
	for i := range machines {
		m := &machines[i]
		if !mayAct[m.Org] {
			continue
		}
		names = append(names, m.Name)
		entry := machineSealInfo{Org: m.Org, Online: online[m.Name]}
		state := s.e2eStateForMachineRow(m)
		switch {
		case !state.Enabled:
			entry.Reason = state.Reason
		case m.PubE2E == "":
			entry.Reason = "this machine has no E2E key — re-enroll it to enable secret push"
		default:
			entry.PubE2E = m.PubE2E
		}
		info[m.Name] = entry
	}
	return info, names, nil
}

// ---- actions ----

// handleUISecretPush receives a browser-sealed push. The form carries
// {machine, name, sealed, csrf} — and MUST NOT carry a value: this handler
// refuses a request that includes one, so a broken page or a tampered form
// cannot turn the UI into a plaintext entry point. The relay itself is the
// console API's own core (relaySealedSecretPush), audited with the acting
// identity instead of a key name.
func (s *Server) handleUISecretPush(w http.ResponseWriter, r *http.Request, sess uiSession) {
	machine := r.PostFormValue("machine")
	name := r.PostFormValue("name")
	sealed := r.PostFormValue("sealed")
	if r.PostForm.Has("value") {
		// Fail closed on a plaintext field, whatever it contains. The message
		// does not repeat the field's contents — they are a captured secret,
		// not an error detail.
		s.logf("ui: secret push form arrived with a plaintext value field (by %q); refusing", sess.Ident.Subject)
		s.uiFail(w, r, http.StatusForbidden,
			"This form sent a value unsealed. The web UI cannot accept that — the browser seals values so this control plane never sees them. Use `mach secrets push <machine> NAME --value-file '-'` instead.")
		return
	}
	if machine == "" || name == "" || sealed == "" {
		s.uiFail(w, r, http.StatusBadRequest,
			"The browser did not seal a value for this push. Scripting is unavailable or the seal support failed to load — use `mach secrets push <machine> NAME --value-file -` from a configured console.")
		return
	}
	m, err := s.st.MachineByName(machine)
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	if m == nil {
		s.uiFail(w, r, http.StatusNotFound, "No machine by that name.")
		return
	}
	if !s.uiMayTouchMachineRow(w, r, sess, m) {
		return
	}
	status, msg := s.relaySealedSecretPush(m, name, sealed, "ui:"+sess.Ident.Subject)
	if status != http.StatusOK {
		s.uiFail(w, r, status, msg)
		return
	}
	s.logf("ui: secret %q pushed to %q (by %q)", name, m.Name, sess.Ident.Subject)
	// One fixed sentence on both paths — same string the scripting-off
	// redirect lands with, so the two paths cannot say different things.
	s.secretsRefresh(w, r, sess, uiNoticeText("secretspushed"), "secretspushed")
}

// handleUISecretDelete removes one secret NAME from one org: the registry row
// and a best-effort delete frame to the org's reachable machines (see
// orgSecretDelete). The name is typed to confirm, the way machine delete is:
// a delete removes what a plaintext exec's injection guard requires, so it
// must not be reachable by a misclick on the wrong row.
func (s *Server) handleUISecretDelete(w http.ResponseWriter, r *http.Request, sess uiSession) {
	org := strings.ToLower(r.PostFormValue("org"))
	name := r.PostFormValue("name")
	if org == "" || name == "" {
		s.uiFail(w, r, http.StatusBadRequest, "org and name are required")
		return
	}
	// The org gate. A member of the org (viewer included) knows these names
	// exist — the page showed them — but only operator-and-better may delete;
	// anyone else gets the same answer an absent name gets, so the UI cannot
	// probe which names exist beyond one's reach (uiMayTouchMachineRow's rule,
	// applied to the registry).
	if sess.roleIn(org) == "" {
		s.uiFail(w, r, http.StatusNotFound, "No secret by that name.")
		return
	}
	if !sess.uiCanActOnOrg(org) {
		s.uiFail(w, r, http.StatusNotFound, "No secret by that name.")
		return
	}

	confirmName := r.PostFormValue("confirm_name")
	if r.PostFormValue("confirm") != "1" || confirmName != name {
		data := secretDeleteConfirmData{Org: org, Name: name, CSRF: sess.CSRF}
		if r.Header.Get("HX-Request") != "" {
			s.renderFragment(w, sess, uiTmpl, "secretdeleteconfirm", data)
			return
		}
		s.renderPage(w, http.StatusOK, sess, "", "Delete secret "+name, uiTmpl, "secretdeleteconfirmpage", data)
		return
	}

	status, msg := s.orgSecretDelete(org, name, "ui:"+sess.Ident.Subject)
	if status != http.StatusOK {
		s.uiFail(w, r, status, msg)
		return
	}
	s.logf("ui: secret %q deleted from org %q (by %q)", name, org, sess.Ident.Subject)
	// The fixed sentences agree on both paths; the htmx path carries the
	// per-machine summary in addition, where a page swap can show it.
	s.secretsRefresh(w, r, sess, uiNoticeText("secretdeleted")+" "+msg, "secretdeleted")
}

// secretsRefresh answers the way the caller can consume, mirroring
// refreshOrRedirect for the secrets page: a swapped-in refreshed region for
// htmx, a redirect with the same fixed notice code for a plain form post. The
// two branches take their sentences from uiNoticeText, so they cannot drift.
func (s *Server) secretsRefresh(w http.ResponseWriter, r *http.Request, sess uiSession, notice, noticeCode string) {
	if r.Header.Get("HX-Request") != "" {
		rows, err := s.secretRowsFor(sess)
		if err != nil {
			s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
			return
		}
		s.renderFragment(w, sess, uiTmpl, "secretsaction", secretsData{Rows: rows, CSRF: sess.CSRF, Notice: notice})
		return
	}
	http.Redirect(w, r, "/ui/secrets?n="+noticeCode, http.StatusSeeOther)
}

// secretDeleteConfirmData carries the typed-name confirmation, the same shape
// the machine delete confirmation uses.
type secretDeleteConfirmData struct {
	Org  string
	Name string
	CSRF string
}

// jsonForPage marshals the seal-info map for the page's data attribute.
// The attribute is escaped by html/template; this only fixes the shape.
func jsonForPage(v map[string]machineSealInfo) string {
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}
