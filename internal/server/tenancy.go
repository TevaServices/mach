package server

// Tenancy helpers: how a caller's org binding meets the machine it names.
//
// The org is a stored fact on every machine row and every API key. What this
// file owns is the join between them: a tenant's key addresses machines by
// their LOCAL name ("web-1"), and the canonical "<org>-<machine>" row the
// rest of the control plane keys on is composed here, from the key's own
// org. A key of org A composing a name can only ever produce names of org A
// — that is the boundary, and it holds without consulting any org list,
// because composition is prefixing, not resolution.
//
// Canonical names remain valid input: an operator who copied one from a
// superadmin view (or an old console holding a stored allowlist) reaches the
// same machine, and the row's stored org is checked against the key's org
// besides — so a canonical name of ANOTHER org is just an unknown machine.

import (
	"strings"

	"github.com/TevaServices/mach/internal/store"
)

// canonicalMachineName composes the machine row name a client's typed name
// refers to, given the caller's org binding. keyOrg == "" means the caller
// has no binding — the transitional shape of a key minted before tenancy
// (the startup backfill stamps every key, so this exists only for stores
// that never met the server) — and the typed name is used as-is, which is
// exactly how keys always behaved.
//
// A name already carrying the caller's own org prefix is taken as the
// canonical form. Anything else is a local name and is prefixed. Nothing
// here can reach another org: the prefix added is always the caller's own.
func canonicalMachineName(keyOrg, typed string) string {
	typed = strings.TrimSpace(typed)
	if keyOrg == "" {
		return typed
	}
	if strings.HasPrefix(typed, keyOrg+"-") {
		return typed
	}
	return store.LocalMachineName(keyOrg, typed)
}

// keyAllowsMachine reports whether an exec-scoped key may act on the
// canonical machine name. Allowlist entries are local names within the
// key's org (validated at mint); canonical entries from keys minted before
// tenancy keep working, because a canonical entry that names a machine of
// another org can never match a machine this key can resolve to anyway —
// the org check on the row is what holds the boundary, and this match is
// about the key's own scope text.
func keyAllowsMachine(scopes, keyOrg, canonical string) bool {
	allowed, all := execAllowlist(scopes)
	if all {
		return true
	}
	local := ""
	if keyOrg != "" && strings.HasPrefix(canonical, keyOrg+"-") {
		local = strings.TrimPrefix(canonical, keyOrg+"-")
	}
	for _, m := range allowed {
		if m == canonical || (local != "" && m == local) {
			return true
		}
	}
	return false
}

// e2eStateForMachineRow is e2eStateFor with the org taken from the machine
// row when it has one. Rows written before tenancy carry "" until backfill;
// for those the prefix resolution (orgOf) is the fallback, which is what the
// flag always did and keeps a not-yet-backfilled row behaving as before.
func (s *Server) e2eStateForMachineRow(m *store.Machine) E2EState {
	if m != nil && m.Org != "" {
		return s.e2eStateForOrg(m.Org)
	}
	return s.e2eStateFor(m.Name)
}

// auditOrgFor resolves the org an audit row for this machine should carry.
// The machine row's stored org is the fact; keyOrg is the fallback for a
// machine that cannot be resolved at all (the row still records which
// tenant's key attempted it). An unresolvable machine of an unbackfilled row
// is best effort: the backfill stamps orgs at startup, so this path is rare
// and conservative.
func (s *Server) auditOrgFor(machine, keyOrg string) string {
	if m, err := s.st.MachineByName(machine); err == nil && m != nil && m.Org != "" {
		return m.Org
	}
	if keyOrg != "" {
		return keyOrg
	}
	// Last resort for the unbound caller: today's prefix resolution, so a
	// global CLI-recorded row keeps its org even before backfill completes.
	if org, ok := s.orgOf(machine); ok {
		return org
	}
	return ""
}
