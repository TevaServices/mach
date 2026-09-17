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
		s.uiRefuse(w, http.StatusBadRequest, "an org must be 2-20 characters: letters, digits and hyphen")
		return
	}
	if s.orgRegistered(org) {
		s.uiRefuse(w, http.StatusConflict, "org is already configured")
		return
	}
	if err := s.st.CreateOrg(org, sess.Ident.Subject); err != nil {
		if errors.Is(err, store.ErrOrgExists) {
			s.uiRefuse(w, http.StatusConflict, "org is already configured")
			return
		}
		s.uiRefuse(w, http.StatusInternalServerError, "store error")
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
		s.uiRefuse(w, http.StatusConflict,
			"org "+org+" comes from MACH_ORG/MACH_ORGS and cannot be removed from here")
		return
	}
	if !s.orgRegistered(org) {
		s.uiRefuse(w, http.StatusNotFound, "unknown org")
		return
	}
	// Refused while machines exist, deliberately. Removing an org does not revoke
	// or delete them — they keep running and their names stay taken — so the
	// operator would silently lose the ability to replace those machines under
	// their existing names, which is a confusing state to discover later.
	machines, err := s.st.ListMachines()
	if err != nil {
		s.uiRefuse(w, http.StatusInternalServerError, "store error")
		return
	}
	if n := countMachinesInOrg(machines, org); n > 0 {
		s.uiRefuse(w, http.StatusConflict,
			"org "+org+" still has "+strconv.Itoa(n)+" machine(s); block, revoke or delete them first")
		return
	}
	if err := s.st.DeleteOrg(org); err != nil {
		s.uiRefuse(w, http.StatusInternalServerError, "store error")
		return
	}
	s.logf("ui: org removed: %q (by %q)", org, sess.Ident.Subject)
	s.refreshOrgs(w, r, sess, "orgremoved")
}

func (s *Server) handleUIOrgE2E(w http.ResponseWriter, r *http.Request, sess uiSession) {
	org := strings.ToLower(strings.TrimSpace(r.PostFormValue("org")))
	mode := strings.ToLower(strings.TrimSpace(r.PostFormValue("mode")))
	if !s.orgRegistered(org) {
		s.uiRefuse(w, http.StatusNotFound, "unknown org")
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
		s.uiRefuse(w, http.StatusBadRequest, "mode must be on, off or inherit")
		return
	}
	if err != nil {
		s.uiRefuse(w, http.StatusInternalServerError, "store error")
		return
	}
	// MACH_E2E still wins over a stored row; say so rather than reporting a write
	// that has no effect on behaviour.
	effective, source := E2EMode(s.st, org)
	s.logf("ui: sealed exec for org %q set to %q, now effective %q (%s) — by %q",
		org, mode, effective, source, sess.Ident.Subject)
	s.refreshOrgs(w, r, sess, "e2eset")
}

func (s *Server) refreshOrgs(w http.ResponseWriter, r *http.Request, sess uiSession, noticeCode string) {
	if r.Header.Get("HX-Request") != "" {
		rows, err := s.orgRows()
		if err != nil {
			http.Error(w, "store error", http.StatusInternalServerError)
			return
		}
		s.renderFragment(w, sess, uiTmpl, "orgs", orgsData{Rows: rows, CSRF: sess.CSRF})
		return
	}
	http.Redirect(w, r, "/ui/orgs?n="+noticeCode, http.StatusSeeOther)
}
