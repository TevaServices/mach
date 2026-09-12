package server

import (
	"log"
	"os"
	"sort"
	"strings"

	"github.com/bcross/mach/internal/store"
)

// envOrgs returns the org prefixes that come from the environment: MACH_ORG
// (the primary) and the comma-separated MACH_ORGS.
func (s *Server) envOrgs() []string {
	var out []string
	for _, v := range []string{s.org, os.Getenv("MACH_ORGS")} {
		for _, o := range strings.Split(v, ",") {
			if o = strings.ToLower(strings.TrimSpace(o)); o != "" {
				out = append(out, o)
			}
		}
	}
	return out
}

// ListOrgs returns the configured org prefixes: the environment's first (the
// primary org, then MACH_ORGS in the order written), then the ones stored in the
// database, deduplicated.
//
// The order is deliberate and not alphabetical — the primary org leads, which is
// what the pair page's org picker has always shown — so stored orgs are appended
// in name order rather than the whole list being sorted.
//
// A database that cannot be read is logged and skipped rather than propagated,
// because this is called from the enrollment paths: an unreadable orgs table
// must not stop a machine enrolling under an org the environment already
// configured.
func (s *Server) ListOrgs() []string {
	out := s.envOrgs()
	if s.st != nil {
		dbOrgs, err := s.st.ListOrgsDB()
		if err != nil {
			log.Printf("server: could not read stored orgs, using the environment's only: %v", err)
		}
		names := make([]string, 0, len(dbOrgs))
		for _, o := range dbOrgs {
			names = append(names, o.Name)
		}
		sort.Strings(names)
		out = append(out, names...)
	}
	seen := map[string]bool{}
	deduped := make([]string, 0, len(out))
	for _, o := range out {
		if !seen[o] {
			seen[o] = true
			deduped = append(deduped, o)
		}
	}
	return deduped
}

// orgPinned reports whether an org is pinned by the environment, and therefore
// cannot be removed from the UI. The same relationship MACH_E2E has to the stored
// E2E setting: the deployment's configuration outranks the database.
func (s *Server) orgPinned(org string) bool {
	for _, o := range s.envOrgs() {
		if o == org {
			return true
		}
	}
	return false
}

// configuredOrgs returns every org with its provenance, for the UI.
func (s *Server) configuredOrgs() ([]store.Org, error) {
	names := s.ListOrgs()
	out := make([]store.Org, 0, len(names))
	for _, n := range names {
		out = append(out, store.Org{Name: n, Pinned: s.orgPinned(n)})
	}
	return out, nil
}

// orgRegistered reports whether the typed org is configured on the server.
func (s *Server) orgRegistered(org string) bool {
	org = strings.ToLower(strings.TrimSpace(org))
	for _, o := range s.ListOrgs() {
		if o == org {
			return true
		}
	}
	return false
}

// resolveOrgForName reports whether a machine name is org-prefixed for any
// configured org, returning the org it resolved to.
//
// Longest-first, matching orgOf: "acme-2-host" belongs to org "acme-2", not to
// "acme", and a bare prefix test would accept both.
//
// Both enrollment paths use this. They did not before — the pair page accepted
// any configured org while the API-key path checked the primary org alone — and
// with orgs now addable from the UI, that asymmetry would make "add an org" do
// nothing for API-key enrollment. It does not weaken the naming invariant: the
// name is still required to be <org>-<machine>, with an org this control plane
// actually has configured.
func (s *Server) resolveOrgForName(name string) (string, bool) {
	orgs := s.ListOrgs()
	sort.Slice(orgs, func(i, j int) bool { return len(orgs[i]) > len(orgs[j]) })
	for _, o := range orgs {
		if store.ValidOrgName(o, name) {
			return o, true
		}
	}
	return "", false
}

// machineInOrg reports whether a machine name carries an org's prefix.
//
// The separator matters: "acme-2-host" belongs to org "acme-2", not to "acme",
// and a bare strings.HasPrefix would say both. Since an org label may itself
// contain a hyphen, the only safe test is the prefix followed by the separator.
// Callers that need longest-match resolution use e2eflag.go's orgOf, which sorts
// by length first; this is the membership test, where the org is already known.
func machineInOrg(machine, org string) bool {
	return strings.HasPrefix(machine, org+"-")
}

// countMachinesInOrg counts a machine slice's members of one org.
func countMachinesInOrg(machines []store.Machine, org string) int {
	n := 0
	for _, m := range machines {
		if machineInOrg(m.Name, org) {
			n++
		}
	}
	return n
}
