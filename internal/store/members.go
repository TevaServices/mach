package store

// UI membership: who may act on which tenant, and how much.
//
// Before tenancy the web UI's only gate was the identity provider: any
// identity the configured issuer verified could block, revoke, delete and
// add orgs. That was honest for a single operator and wrong for several
// tenants, so the membership rows below are the authorization model the UI
// now layers on top of OIDC — OIDC answers "who are you", membership answers
// "what may you touch". A signed-in identity with no membership row may do
// nothing, which is the fail-closed direction: authorization is granted by
// a row, never by the absence of one.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

// Member roles, from strongest to weakest. superadmin is the control plane's
// global role: it may manage orgs (create, remove) and act within every org,
// including orgs it has no row in. admin is full control INSIDE one org —
// its members, its keys, its machines, its settings — and no reach outside
// it. operator executes and approves within the org; viewer reads.
const (
	RoleSuperadmin = "superadmin"
	RoleAdmin      = "admin"
	RoleOperator   = "operator"
	RoleViewer     = "viewer"
)

// superOrg is the org column value of a superadmin row: a wildcard, because
// a superadmin is a member of every org by construction rather than by row.
const superOrg = "*"

// ValidMemberRole reports whether role is one the store will record.
// Exported because the minting surfaces — the CLI and the web UI — must ask
// the store's rule rather than growing their own copies of it.
func ValidMemberRole(role string) bool {
	switch role {
	case RoleSuperadmin, RoleAdmin, RoleOperator, RoleViewer:
		return true
	}
	return false
}

// ErrUnknownMember is returned when a removal names a row that does not
// exist, so a typo is an error rather than a printed success.
var ErrUnknownMember = errors.New("unknown member")

// Member is one identity's binding to one org.
type Member struct {
	ID        int64
	Org       string
	Email     string
	Subject   string
	Role      string
	CreatedAt string
	CreatedBy string
}

// memberCols is the read shape; the table has no secrets, so listing it
// whole is fine (unlike API keys, whose hash columns must stay unselected).
const memberCols = `id, org, email, subject, role, created_at, created_by`

func scanMember(row interface{ Scan(...any) error }) (*Member, error) {
	m := &Member{}
	if err := row.Scan(&m.ID, &m.Org, &m.Email, &m.Subject, &m.Role, &m.CreatedAt, &m.CreatedBy); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return m, nil
}

// normalizeEmail is the canonical form a member is looked up by. Sign-in
// matches on email, so the same address must always hash to the same row —
// case differences in the IdP's response must not mint a second identity.
func normalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

// AddMember records a binding. org is '*' only for a superadmin row; a role
// checked here is checked nowhere else, which is the point.
func (s *Store) AddMember(org, email, subject, role, createdBy string) error {
	org = strings.ToLower(strings.TrimSpace(org))
	email = normalizeEmail(email)
	if !ValidMemberRole(role) {
		return fmt.Errorf("invalid member role %q (use superadmin, admin, operator or viewer)", role)
	}
	if role == RoleSuperadmin {
		if org != "" && org != superOrg {
			return errors.New("a superadmin row is org '*' — pass an empty org")
		}
		org = superOrg
	} else if !ValidOrgLabel(org) {
		return fmt.Errorf("invalid org %q", org)
	}
	if email == "" || !strings.Contains(email, "@") {
		return errors.New("member email must be an address")
	}
	_, err := s.exec(`INSERT INTO ui_members (org, email, subject, role, created_at, created_by)
		VALUES (?,?,?,?,?,?)`, org, email, subject, role, now(), createdBy)
	return err
}

// RemoveMember deletes one binding. Returns ErrUnknownMember when the row is
// absent, so the caller can refuse a stale view instead of pretending.
func (s *Store) RemoveMember(org, email string) error {
	org = strings.ToLower(strings.TrimSpace(org))
	if org != superOrg && !ValidOrgLabel(org) {
		return fmt.Errorf("invalid org %q", org)
	}
	res, err := s.exec(`DELETE FROM ui_members WHERE org=? AND email=?`, org, normalizeEmail(email))
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return fmt.Errorf("%w: %s@%s", ErrUnknownMember, normalizeEmail(email), org)
	}
	return nil
}

// ListMembers returns membership rows, newest first. org scopes to one org
// ("", for the host CLI and the superadmin's global view, lists all —
// including the wildcard superadmin rows).
func (s *Store) ListMembers(org string) ([]Member, error) {
	q := `SELECT ` + memberCols + ` FROM ui_members`
	var args []any
	if org != "" {
		q += ` WHERE org=?`
		args = append(args, org)
	}
	q += ` ORDER BY id DESC`
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// MembersByEmail returns every binding of one identity — the orgs it belongs
// to and its role in each. This is what a sign-in resolves against: no rows
// means the identity may do nothing, whatever the issuer said about it.
func (s *Store) MembersByEmail(email string) ([]Member, error) {
	rows, err := s.query(`SELECT `+memberCols+` FROM ui_members WHERE email=? ORDER BY id`, normalizeEmail(email))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Member
	for rows.Next() {
		m, err := scanMember(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// HasAnyMember reports whether any membership row exists. The bootstrap
// question: a fresh control plane has none, and the CLI is how the first
// superadmin is created — the UI's fail-closed gate means an identity with
// no row can do nothing, so the first member cannot self-create in the UI.
func (s *Store) HasAnyMember() (bool, error) {
	var one int
	err := s.queryRow(`SELECT 1 FROM ui_members LIMIT 1`).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
