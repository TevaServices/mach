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
	"strconv"
	"strings"

	"github.com/bcross/mach/internal/store"
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

// memberData is one org's membership view.
//
// Keys are split into two groups because they have no org column — scopes is a
// free string — so membership is *derived*, and presenting a single list would
// imply keys belong to an org when they do not.
type memberData struct {
	Org        string
	Pinned     bool
	Machines   []fleetRow
	ScopedKeys []store.APIKeyInfo
	FleetKeys  []store.APIKeyInfo
	CSRF       string
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
	orgs, err := s.configuredOrgs()
	if err != nil {
		return nil, err
	}
	machines, err := s.st.ListMachines()
	if err != nil {
		return nil, err
	}
	rows := make([]orgRow, 0, len(orgs))
	for _, o := range orgs {
		// E2EMode reports the effective setting and where it came from, so a
		// MACH_E2E pin is shown as the pin rather than as the stored value.
		mode, source := E2EMode(s.st, o.Name)
		rows = append(rows, orgRow{
			Name:       o.Name,
			Pinned:     o.Pinned,
			Machines:   countMachinesInOrg(machines, o.Name),
			E2EEnabled: mode == e2eOn,
			E2ESource:  source,
		})
	}
	return rows, nil
}

func (s *Server) orgMembership(org string) (memberData, error) {
	rows, err := s.fleetRows()
	if err != nil {
		return memberData{}, err
	}
	data := memberData{Org: org, Pinned: s.orgPinned(org)}
	mode, source := E2EMode(s.st, org)
	data.E2EOn = mode == e2eOn
	data.E2EMode = mode
	data.E2ESource = source
	_, data.E2EOverridden = storedE2E(s.st, e2eOrgKey(org))
	data.E2EPinned = strings.TrimSpace(os.Getenv(e2eEnv)) != ""
	for _, r := range rows {
		if machineInOrg(r.Name, org) {
			data.Machines = append(data.Machines, r)
		}
	}
	keys, err := s.st.ListAPIKeys()
	if err != nil {
		return memberData{}, err
	}
	for _, k := range keys {
		switch {
		case keyScopedToOrg(k.Scopes, org):
			data.ScopedKeys = append(data.ScopedKeys, k)
		case keyFleetWide(k.Scopes):
			data.FleetKeys = append(data.FleetKeys, k)
		}
	}
	return data, nil
}

// keyScopedToOrg reports whether a key's exec allowlist names a machine in this
// org. It reuses the authorization path's own scope parser rather than splitting
// the scope string a second way — a second parser is how a key gets reported as
// belonging somewhere it cannot actually reach.
func keyScopedToOrg(scopes, org string) bool {
	allowed, all := execAllowlist(scopes)
	if all {
		return false // fleet-wide, so not org-scoped
	}
	for _, m := range allowed {
		if machineInOrg(m, org) {
			return true
		}
	}
	return false
}

// keyFleetWide reports whether a key reaches every org. exec:* does; so do
// readonly and enroll, which are not machine-scoped at all — readonly reads the
// whole fleet and enroll can enroll under any configured org.
func keyFleetWide(scopes string) bool {
	if hasScope(scopes, "readonly") || hasScope(scopes, "enroll") {
		return true
	}
	_, all := execAllowlist(scopes)
	return all
}

// ---- actions ----

func (s *Server) handleUIOrgAdd(w http.ResponseWriter, r *http.Request, sess uiSession) {
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
	// Refused while machines exist, deliberately. Removing an org does not revoke
	// or delete them — they keep running and their names stay taken — so the
	// operator would silently lose the ability to replace those machines under
	// their existing names, which is a confusing state to discover later.
	machines, err := s.st.ListMachines()
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return
	}
	if n := countMachinesInOrg(machines, org); n > 0 {
		s.uiFail(w, r, http.StatusConflict,
			"org "+org+" still has "+strconv.Itoa(n)+" machine(s); block, revoke or delete them first")
		return
	}
	if err := s.st.DeleteOrg(org); err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
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
			data, err := s.orgMembership(org)
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
