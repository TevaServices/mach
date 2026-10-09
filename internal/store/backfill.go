package store

// One-time backfills for the tenancy migration. Rows written before org
// existed carry '' (see 0004_tenancy.sql) and are stamped here, at server
// startup, from facts the caller holds — the configured org list, the
// primary org for keys. Every function is idempotent: it touches only rows
// still marked '', so a restart after a partial run completes the job and a
// steady state runs costs one indexed query.

import "log"

// BackfillMachineOrgs stamps each org-less machine with the org its
// canonical name belongs to, resolved longest-first against the orgs the
// caller lists (the environment's and the database's, which is what
// enrollment resolution always consulted). A machine whose name matches no
// configured org keeps ” — it belongs to no tenant, is visible to none of
// them, and the server's startup log names it so the operator can decide
// what it is rather than the store guessing.
//
// Returns the number of rows filled and the names left unresolved.
func (s *Store) BackfillMachineOrgs(orgs []string) (filled int, unresolved []string, err error) {
	rows, err := s.query(`SELECT id, name FROM machines WHERE org=''`)
	if err != nil {
		return 0, nil, err
	}
	type row struct {
		id   int64
		name string
	}
	var pending []row
	for rows.Next() {
		var r row
		if err := rows.Scan(&r.id, &r.name); err != nil {
			rows.Close()
			return 0, nil, err
		}
		pending = append(pending, r)
	}
	if err := rows.Err(); err != nil {
		return 0, nil, err
	}
	rows.Close()

	// Longest first, for the same reason enrollment resolution is: org labels
	// may themselves contain a hyphen, so "acme-2-host" belongs to "acme-2"
	// and a first-dash split would say "acme".
	sorted := append([]string(nil), orgs...)
	for i := 0; i < len(sorted); i++ {
		for j := i + 1; j < len(sorted); j++ {
			if len(sorted[j]) > len(sorted[i]) {
				sorted[i], sorted[j] = sorted[j], sorted[i]
			}
		}
	}
	for _, r := range pending {
		org := ""
		for _, o := range sorted {
			if ValidOrgName(o, r.name) {
				org = o
				break
			}
		}
		if org == "" {
			unresolved = append(unresolved, r.name)
			continue
		}
		if _, err := s.exec(`UPDATE machines SET org=? WHERE id=? AND org=''`, org, r.id); err != nil {
			return filled, unresolved, err
		}
		filled++
	}
	return filled, unresolved, nil
}

// BackfillAPIKeyOrgs stamps every org-less API key with the deployment's
// primary org. Keys predate per-org bindings; the keys that minted them
// belonged to the one operator, and that operator's org is the honest
// tenant to bind them to — logged at startup, not silently applied.
//
// There is no "key of every org" escape hatch: it would make the boundary
// permanent soft for old credentials, which is the one shape of backfill
// tenancy must not have.
func (s *Store) BackfillAPIKeyOrgs(org string) (int64, error) {
	if org == "" {
		return 0, nil
	}
	res, err := s.exec(`UPDATE api_keys SET org=? WHERE org=''`, org)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return 0, err
	}
	return n, nil
}

// logBackfill reports the backfill's outcome the same way the migration
// runner reports its own: what changed, and what needs a human decision.
func logBackfill(filled int, unresolved []string, keyFilled int64) {
	if filled > 0 {
		log.Printf("store: tenancy backfill: stamped %d machine(s) with their org", filled)
	}
	for _, name := range unresolved {
		log.Printf("store: WARNING: machine %q matches no configured org — it belongs to no tenant "+
			"and no org-scoped key can reach it; enroll it again or delete it", name)
	}
	if keyFilled > 0 {
		log.Printf("store: tenancy backfill: bound %d existing API key(s) to the primary org", keyFilled)
	}
}

// BackfillTenancy runs both backfills and logs the outcome. This is the
// entry point the server calls at startup; the individual backfills stay
// separate so tests can drive them directly.
func (s *Store) BackfillTenancy(primaryOrg string, orgs []string) {
	filled, unresolved, err := s.BackfillMachineOrgs(orgs)
	if err != nil {
		log.Printf("store: tenancy backfill failed for machines: %v", err)
		return
	}
	keyFilled, kerr := s.BackfillAPIKeyOrgs(primaryOrg)
	if kerr != nil {
		log.Printf("store: tenancy backfill failed for API keys: %v", kerr)
		return
	}
	logBackfill(filled, unresolved, keyFilled)
}
