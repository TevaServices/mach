package server

// UI authorization: what a signed-in identity may do, decided from the
// membership rows carried on its session.
//
// Before tenancy the UI's only gate was the identity provider — any identity
// it verified could act on everything. Membership replaces that with an
// explicit model, layered ON TOP of the issuer gate (invariant 18's
// fail-closed configuration is untouched: with no MACH_OIDC_* there are no
// UI routes at all, and within the UI the membership rows are the
// authorization model).
//
// The direction of failure is the one a boundary needs: an identity with no
// membership rows may do nothing, and an action on an org the identity is
// not a member of is refused with the same "not found" answer an absent
// target gets, so the UI cannot be used to learn which orgs or machines
// exist.

import (
	"net/http"

	"github.com/TevaServices/mach/internal/store"
)

// isSuper reports whether the session's identity holds the wildcard
// superadmin role. Superadmins manage orgs and may act within every org,
// including ones they have no row in.
func (sess uiSession) isSuper() bool {
	for _, m := range sess.Members {
		if m.Role == store.RoleSuperadmin {
			return true
		}
	}
	return false
}

// roleIn returns the session's strongest role within one org, or "" when the
// identity is not a member of it. Superadmins are implicitly admin of every
// org.
func (sess uiSession) roleIn(org string) string {
	role := ""
	if sess.isSuper() {
		role = store.RoleAdmin
	}
	for _, m := range sess.Members {
		if m.Org != org {
			continue
		}
		switch {
		case m.Role == store.RoleAdmin:
			role = store.RoleAdmin
		case m.Role == store.RoleOperator && role != store.RoleAdmin:
			role = store.RoleOperator
		case m.Role == store.RoleViewer && role == "":
			role = store.RoleViewer
		}
	}
	return role
}

// memberOrgs lists the orgs the session may see (superadmin: every org is
// visible through orgRows, so this returns the member rows' orgs only).
func (sess uiSession) memberOrgs() []string {
	var out []string
	seen := map[string]bool{}
	for _, m := range sess.Members {
		if m.Role == store.RoleSuperadmin || m.Org == "" || seen[m.Org] {
			continue
		}
		seen[m.Org] = true
		out = append(out, m.Org)
	}
	return out
}

// roleAtLeast orders the non-superadmin roles: viewer < operator < admin.
// The comparison lives here rather than as string compares at every gate,
// so the ordering is written once.
func roleAtLeast(role, need string) bool {
	rank := map[string]int{
		store.RoleViewer:   1,
		store.RoleOperator: 2,
		store.RoleAdmin:    3,
	}
	return rank[role] >= rank[need]
}

// uiCanActOnOrg reports whether this session may take an operator action
// (block, revoke, delete, approve, settings) within an org.
func (sess uiSession) uiCanActOnOrg(org string) bool {
	return roleAtLeast(sess.roleIn(org), store.RoleOperator)
}

// uiCanAdminOrg reports whether this session may administer an org: its
// members, its keys, its settings.
func (sess uiSession) uiCanAdminOrg(org string) bool {
	return roleAtLeast(sess.roleIn(org), store.RoleAdmin)
}

// uiMayTouchMachineRow is the gate every machine action passes before it
// acts: the operator must hold operator-or-better IN THE MACHINE'S ORG. A
// machine of another org, and a machine of no org (a row the backfill never
// resolved), is answered "not found" — the same response an absent name
// gets — so the UI cannot be probed for which machines exist outside a
// session's reach. Superadmins act anywhere; that is what the role means.
// Writes the refusal and reports false when the answer is no.
func (s *Server) uiMayTouchMachineRow(w http.ResponseWriter, r *http.Request, sess uiSession, m *store.Machine) bool {
	if sess.isSuper() {
		return true
	}
	if !sess.uiCanActOnOrg(m.Org) {
		s.uiFail(w, r, http.StatusNotFound, "No machine by that name.")
		return false
	}
	return true
}

// uiMayTouchMachine is uiMayTouchMachineRow for a caller that has not loaded
// the row yet.
func (s *Server) uiMayTouchMachine(w http.ResponseWriter, r *http.Request, sess uiSession, name string) bool {
	m, err := s.st.MachineByName(name)
	if err != nil {
		s.uiFail(w, r, http.StatusInternalServerError, "The database could not be read. Nothing was changed.")
		return false
	}
	if m == nil {
		s.uiFail(w, r, http.StatusNotFound, "No machine by that name.")
		return false
	}
	return s.uiMayTouchMachineRow(w, r, sess, m)
}
