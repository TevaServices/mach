package server

// Org administration for the web UI: the org list, one org's membership view, and
// the add / remove / sealed-exec actions.
//
// Orgs were environment-only before this. They now live in a table as well, with
// MACH_ORG and MACH_ORGS acting as a pin the UI cannot remove — the same
// relationship MACH_E2E has to the stored sealed-exec setting.

import (
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/TevaServices/mach/internal/store"
	"github.com/TevaServices/mach/internal/version"
)

type orgRow struct {
	Name       string
	Pinned     bool
	Machines   int
	E2EEnabled bool
	E2ESource  string
}

type orgsData struct {
	Rows []orgRow
	CSRF string
	// Notice is the fixed sentence for the action that just happened, rendered
	// out of band by the *action* defines. See fleetData.Notice.
	Notice string
}

// memberData is one org's membership view. Keys are org-bound rows now, so
// the org page lists exactly the keys whose binding is this org — a stored
// fact, not a derivation from the scope text.
type memberData struct {
	Org        string
	Pinned     bool
	Machines   []fleetRow
	ScopedKeys []store.APIKeyInfo
	// CanRemove gates the remove-org form: only a superadmin sees it. An org
	// with machines cannot be removed at all (store.DeleteOrg refuses), and
	// a pinned org cannot be removed from the UI.
	CanRemove bool
	CSRF      string
	// E2EOn is the *effective* value for this org — what a command sent to one of
	// its machines will actually do — and E2ESource says where it came from.
	// E2EOverridden separates "this org has its own setting" from "this org
	// follows the fleet default", which the On/Off buttons alone cannot express:
	// both can read on, and only one of them can be cleared.
	E2EOn         bool
	E2EMode       string
	E2ESource     string
	E2EOverridden bool
	// E2EPinned is true when MACH_E2E is set, in which case no stored setting for
	// this org can take effect and the page says so instead of offering a control
	// that does nothing.
	E2EPinned bool
	// Notice is the fixed sentence for the action that just happened, rendered
	// out of band by the *action* defines. See fleetData.Notice.
	Notice string
}

func (s *Server) orgRows() ([]orgRow, error) {
	return s.orgRowsFor(nil)
}

// orgRowsFor is the org listing a session may see: nil (or an empty slice)
// means every org — the superadmin's view and the CLI's; a session's list is
// its member orgs. Machine counts read the stored org column, the same fact
// enrollment wrote, rather than re-deriving membership from name prefixes.
func (s *Server) orgRowsFor(orgs []string) ([]orgRow, error) {
	configured, err := s.configuredOrgs()
	if err != nil {
		return nil, err
	}
	allowed := map[string]bool{}
	for _, o := range orgs {
		allowed[o] = true
	}
	machines, err := s.st.ListMachines()
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	for _, m := range machines {
		counts[m.Org]++
	}
	rows := make([]orgRow, 0, len(configured))
	for _, o := range configured {
		if allowed != nil && len(allowed) > 0 && !allowed[o.Name] {
			continue
		}
		// E2EMode reports the effective setting and where it came from, so a
		// MACH_E2E pin is shown as the pin rather than as the stored value.
		mode, source := E2EMode(s.st, o.Name)
		rows = append(rows, orgRow{
			Name:       o.Name,
			Pinned:     o.Pinned,
			Machines:   counts[o.Name],
			E2EEnabled: mode == e2eOn,
			E2ESource:  source,
		})
	}
	return rows, nil
}

func (s *Server) orgMembership(org string, sess uiSession) (memberData, error) {
	machines, err := s.st.ListMachinesByOrg(org)
	if err != nil {
		return memberData{}, err
	}
	online := s.br.OnlineNames()
	data := memberData{Org: org, Pinned: s.orgPinned(org)}
	mode, source := E2EMode(s.st, org)
	data.E2EOn = mode == e2eOn
	data.E2EMode = mode
	data.E2ESource = source
	_, data.E2EOverridden = storedE2E(s.st, e2eOrgKey(org))
	data.E2EPinned = strings.TrimSpace(os.Getenv(e2eEnv)) != ""
	for _, m := range machines {
		data.Machines = append(data.Machines, fleetRow{
			Name: m.Name, Hostname: m.Hostname, OS: m.OS, Arch: m.Arch,
			AgentVer:  m.AgentVer,
			AgentSkew: m.AgentVer != "" && m.AgentVer != version.Version,
			Online:    online[m.Name],
			Blocked:   m.Blocked, Revoked: m.Revoked, Temporary: m.Temporary,
		})
	}
	// Keys are org-bound rows now, so membership is a stored fact and the
	// derived prefix-matching helpers are gone: an org page lists the keys
	// whose binding is this org, and — for the superadmin's convenience —
	// nothing else. There is no third bucket to leak into.
	keys, err := s.st.ListAPIKeys(org)
	if err != nil {
		return memberData{}, err
	}
	data.ScopedKeys = keys
	data.CanRemove = sess.isSuper() && !data.Pinned
	return data, nil
}

// ---- actions ----

func (s *Server) handleUIOrgAdd(w http.ResponseWriter, r *http.Request, sess uiSession) {
	if !sess.isSuper() {
		// Org management is the superadmin's power: creating an org makes a
		// prefix enrollable, which is exactly the capability SECURITY-NOTES
		// flags as new when it left the CLI. A non-super gets the same
		// refusal whether or not the org exists, so the page cannot probe.
		s.uiFail(w, r, http.StatusForbidden, "Only a superadmin can add orgs.")
		return
	}
	org := strings.ToLower(strings.TrimSpace(r.PostFormValue("org")))
	if !store.ValidOrgLabel(org) {
		s.uiFail(w, r, http.StatusBadRequest, "an org must be 2-20 characters: letters, digits and hyphen")
		return
	}
	if s.orgRegistered(org) {
		s.uiFail(w, r, http.StatusConflict, "org is already configured")
		return
	}
	if err := s.st.CreateOrg(org, sess.Ident.Subject); err != nil {
		if errors.Is(err, store.ErrOrgExists) {
			s.uiFail(w, r, http.StatusConflict, "org is already configured")
			return
		}
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	// Logged with the operator's subject: org changes are not per-machine, so
	// they do not belong in the per-machine audit table, but they are still
	// security-relevant and must leave a durable record naming who did it.
	s.logf("ui: org added: %q (by %q)", org, sess.Ident.Subject)
	s.refreshOrgs(w, r, sess, "orgadded")
}

func (s *Server) handleUIOrgRemove(w http.ResponseWriter, r *http.Request, sess uiSession) {
	if !sess.isSuper() {
		s.uiFail(w, r, http.StatusForbidden, "Only a superadmin can remove orgs.")
		return
	}
	org := strings.ToLower(strings.TrimSpace(r.PostFormValue("org")))
	if s.orgPinned(org) {
		// A FIXED sentence, with no echo of the submitted value — every other
		// refusal in the UI is a fixed literal, and this one used to interpolate
		// the posted org. The echo was bounded rather than arbitrary: reaching this
		// branch at all requires orgPinned, so the value could only ever be a name
		// that is already printed in the org list. It is still request text
		// reaching a rendered page, and removing the whole class is cheaper than
		// reasoning about how narrow it is.
		s.uiFail(w, r, http.StatusConflict,
			"That org comes from the environment (MACH_ORG/MACH_ORGS) and cannot be removed from here.")
		return
	}
	if !s.orgRegistered(org) {
		s.uiFail(w, r, http.StatusNotFound, "No org by that name.")
		return
	}
	// Refused while machines exist — the guard lives in store.DeleteOrg now,
	// so every caller of the removal gets it, not only this handler. The
	// error's own sentence is surfaced rather than paraphrased, because it
	// counts the machines the operator must deal with first.
	if err := s.st.DeleteOrg(org); err != nil {
		s.uiFail(w, r, http.StatusConflict, err.Error())
		return
	}
	s.logf("ui: org removed: %q (by %q)", org, sess.Ident.Subject)
	s.refreshOrgs(w, r, sess, "orgremoved")
}

func (s *Server) handleUIOrgE2E(w http.ResponseWriter, r *http.Request, sess uiSession) {
	org := strings.ToLower(strings.TrimSpace(r.PostFormValue("org")))
	mode := strings.ToLower(strings.TrimSpace(r.PostFormValue("mode")))
	if !s.orgRegistered(org) {
		s.uiFail(w, r, http.StatusNotFound, "No org by that name.")
		return
	}
	if !sess.uiCanAdminOrg(org) {
		s.uiFail(w, r, http.StatusForbidden, "Only an admin of this org can change its E2E setting.")
		return
	}
	var err error
	switch mode {
	case "on":
		err = SetE2E(s.st, org, true)
	case "off":
		err = SetE2E(s.st, org, false)
	case "inherit":
		err = ClearE2E(s.st, org)
	default:
		s.uiFail(w, r, http.StatusBadRequest, "mode must be on, off or inherit")
		return
	}
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	// MACH_E2E still wins over a stored row; say so rather than reporting a write
	// that has no effect on behaviour.
	effective, source := E2EMode(s.st, org)
	s.logf("ui: E2E for org %q set to %q, now effective %q (%s) — by %q",
		org, mode, effective, source, sess.Ident.Subject)

	// Answer where the control lives. The orgs list carries no E2E buttons any
	// more, so the org's own page is the normal case; the list branch is kept for
	// any client still posting without the view field.
	if strings.ToLower(strings.TrimSpace(r.PostFormValue("view"))) == "member" {
		if r.Header.Get("HX-Request") != "" {
			data, err := s.orgMembership(org, sess)
			if err != nil {
				s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
				return
			}
			data.CSRF = sess.CSRF
			data.Notice = uiNoticeText("e2eset")
			s.renderFragment(w, sess, uiTmpl, "orge2eaction", data)
			return
		}
		// Built from the org we just validated against the configured list, never
		// from request text, so this cannot become an open redirect.
		http.Redirect(w, r, "/ui/orgs/"+org+"?n=e2eset", http.StatusSeeOther)
		return
	}
	s.refreshOrgs(w, r, sess, "e2eset")
}

func (s *Server) refreshOrgs(w http.ResponseWriter, r *http.Request, sess uiSession, noticeCode string) {
	if r.Header.Get("HX-Request") != "" {
		rows, err := s.orgRows()
		if err != nil {
			s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
			return
		}
		s.renderFragment(w, sess, uiTmpl, "orgsaction", orgsData{
			Rows: rows, CSRF: sess.CSRF, Notice: uiNoticeText(noticeCode),
		})
		return
	}
	http.Redirect(w, r, "/ui/orgs?n="+noticeCode, http.StatusSeeOther)
}
