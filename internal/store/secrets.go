package store

// The secrets registry: names + org, never values. See 0005_secrets.sql for
// what the table is for and why it has no value column — the absence of the
// field is the control, the same way APIKeyInfo's missing hash columns are.

import (
	"database/sql"
	"errors"
	"time"
)

// SecretInfo is one registry row as any surface may see it: there is
// nothing secret in it, by construction.
type SecretInfo struct {
	Org        string
	Name       string
	CreatedAt  string
	CreatedBy  string
	LastSeenAt string
}

const secretCols = `org, name, created_at, created_by, last_seen_at`

func scanSecret(row interface{ Scan(...any) error }) (*SecretInfo, error) {
	si := &SecretInfo{}
	if err := row.Scan(&si.Org, &si.Name, &si.CreatedAt, &si.CreatedBy, &si.LastSeenAt); err != nil {
		return nil, err
	}
	return si, nil
}

// UpsertSecret records that machine org now holds secret name, refreshing
// last_seen_at on an existing row. It is written from two places that are
// both evidence the machine holds the name: a successful push, and an
// announce from the machine itself. The upsert is spelled the shared way
// (ON CONFLICT) so both drivers agree.
func (s *Store) UpsertSecret(org, name, createdBy string) error {
	ts := now()
	_, err := s.exec(`INSERT INTO secrets (org, name, created_at, created_by, last_seen_at)
		VALUES (?,?,?,?,?)
		ON CONFLICT(org, name) DO UPDATE SET last_seen_at=excluded.last_seen_at`,
		org, name, ts, createdBy, ts)
	return err
}

// RemoveSecret drops one registry row. It is bookkeeping, not revocation —
// the machine still holds the value until it is removed on the box — so the
// return value reports presence the way RevokeAPIKey does: an unknown name
// is false, and the caller decides whether that is an error.
func (s *Store) RemoveSecret(org, name string) (bool, error) {
	res, err := s.exec(`DELETE FROM secrets WHERE org=? AND name=?`, org, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	return n > 0, nil
}

// ListSecrets returns one org's registry rows, ordered by name. org ""
// lists every org's rows — the host CLI's view, and no other caller's.
func (s *Store) ListSecrets(org string) ([]SecretInfo, error) {
	q := `SELECT ` + secretCols + ` FROM secrets`
	var args []any
	if org != "" {
		q += ` WHERE org=?`
		args = append(args, org)
	}
	q += ` ORDER BY org, name`
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretInfo
	for rows.Next() {
		si, err := scanSecret(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *si)
	}
	return out, rows.Err()
}

// SecretKnown reports whether the registry holds (org, name). The
// injection guard asks exactly this, one indexed probe per command.
func (s *Store) SecretKnown(org, name string) (bool, error) {
	var one int
	err := s.queryRow(`SELECT 1 FROM secrets WHERE org=? AND name=?`, org, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// TouchSecret refreshes last_seen_at without touching provenance — the
// registry's record of a live list from the machine itself.
func (s *Store) TouchSecret(org, name string) error {
	_, err := s.exec(`UPDATE secrets SET last_seen_at=? WHERE org=? AND name=?`,
		time.Now().UTC().Format(time.RFC3339), org, name)
	return err
}
