package server

import (
	"os"
	"strings"
)

// ListOrgs returns configured org prefixes: MACH_ORG (primary) first, then
// any extras from the comma-separated MACH_ORGS env. Deduplicated, ordered.
func (s *Server) ListOrgs() []string {
	var out []string
	seen := map[string]bool{}
	for _, v := range []string{s.org, os.Getenv("MACH_ORGS")} {
		for _, o := range strings.Split(v, ",") {
			o = strings.ToLower(strings.TrimSpace(o))
			if o == "" || seen[o] {
				continue
			}
			seen[o] = true
			out = append(out, o)
		}
	}
	return out
}

// orgRegistered reports whether the typed org is configured on the server.
func (s *Server) orgRegistered(org string) bool {
	for _, o := range s.ListOrgs() {
		if o == org {
			return true
		}
	}
	return false
}
