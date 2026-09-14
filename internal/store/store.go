// Package store implements the control plane's persistence: machines,
// API keys, pairing sessions, and the command audit log. SQLite (pure-Go
// driver, single file, WAL mode) is the default; a postgres:// DSN swaps in
// Postgres for fleets that outgrow a single writer. One schema, one set of
// statements, translated per driver.
package store

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

// ErrOrgExists is returned by CreateOrg when the prefix is already configured.
// A sentinel rather than the driver's duplicate-key error, which is spelled
// differently by the two engines.
var ErrOrgExists = errors.New("org already exists")

type Store struct {
	db    *sql.DB
	known string // "sqlite" or "postgres" — feature gating is driver-neutral
}

// Open opens the store. DSN forms:
//   - filesystem path (e.g. /data/mach.db) → SQLite, WAL, busy_timeout 5s
//   - postgres:// or postgresql:// URL      → Postgres (multi-writer-ready;
//     identical schema via the same migration SQL)
//
// Postgres support removes the single-writer limitation for larger fleets;
// the schema is deliberately portable (AUTOINCREMENT-free, TEXT timestamps).
func Open(path string) (*Store, error) {
	if strings.HasPrefix(path, "postgres://") || strings.HasPrefix(path, "postgresql://") {
		db, err := sql.Open("pgx", path)
		if err != nil {
			return nil, err
		}
		db.SetMaxOpenConns(25)
		s := &Store{db: db, known: "postgres"}
		if err := s.migrate(); err != nil {
			db.Close()
			return nil, fmt.Errorf("postgres migrate: %w", err)
		}
		if err := s.verifySchema(); err != nil {
			db.Close()
			return nil, fmt.Errorf("postgres schema: %w", err)
		}
		return s, nil
	}
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	// WAL allows concurrent readers alongside the single writer; cap
	// connections so writes serialize predictably in-process.
	db.SetMaxOpenConns(1)
	s := &Store{db: db, known: "sqlite"}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	if err := s.verifySchema(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

// Known reports the backing driver ("sqlite" or "postgres").
func (s *Store) Known() string { return s.known }

func (s *Store) Close() error { return s.db.Close() }

// idColumn is the auto-assigning primary key for each driver. SQLite's
// INTEGER PRIMARY KEY is a rowid alias that fills itself in; Postgres needs
// BIGSERIAL for the same behavior. Everything else about the schema is shared,
// so the statements below are written once.
func (s *Store) idColumn() string {
	if s.known == "postgres" {
		return "BIGSERIAL PRIMARY KEY"
	}
	return "INTEGER PRIMARY KEY"
}

// The schema itself is not a const here any more: it is the embedded
// migration set (see migrate.go and migrations/0001_baseline.sql), applied
// by migrate() and checksum-verified on every open.

// ---- placeholder and connection plumbing ----
//
// Statements are written once in the "?" form and translated for the driver,
// rather than maintained twice: two copies of every query is how the two
// dialects drift apart. Postgres (pgx) takes positional parameters, sqlite
// takes "?".

// rebind rewrites ? placeholders to $1, $2 … for Postgres. A ? inside a quoted
// literal or identifier is left alone: it is data, not a parameter.
func (s *Store) rebind(q string) string {
	if s.known != "postgres" || !strings.ContainsRune(q, '?') {
		return q
	}
	var b strings.Builder
	b.Grow(len(q) + 8)
	n := 0
	var quote byte
	for i := 0; i < len(q); i++ {
		c := q[i]
		switch {
		case quote != 0:
			b.WriteByte(c)
			if c == quote {
				// '' inside a literal is an escaped quote, not the end of it.
				if i+1 < len(q) && q[i+1] == quote {
					b.WriteByte(q[i+1])
					i++
					continue
				}
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
			b.WriteByte(c)
		case c == '?':
			n++
			b.WriteString("$" + strconv.Itoa(n))
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func (s *Store) exec(q string, args ...any) (sql.Result, error) {
	return s.db.Exec(s.rebind(q), args...)
}

func (s *Store) query(q string, args ...any) (*sql.Rows, error) {
	return s.db.Query(s.rebind(q), args...)
}

func (s *Store) queryRow(q string, args ...any) *sql.Row {
	return s.db.QueryRow(s.rebind(q), args...)
}

// storeTx is a transaction with the same placeholder translation, so a query
// written for one driver runs on both inside and outside a transaction.
type storeTx struct {
	tx *sql.Tx
	s  *Store
}

func (t *storeTx) exec(q string, args ...any) (sql.Result, error) {
	return t.tx.Exec(t.s.rebind(q), args...)
}

func (t *storeTx) queryRow(q string, args ...any) *sql.Row {
	return t.tx.QueryRow(t.s.rebind(q), args...)
}

// verifySchema refuses to run against a database created by an earlier
// schema version. There is no migration path: mach is pre-1.0 and has never
// shipped, so a stale file is a development artifact — and quietly reading
// one with different column semantics (or silently missing the indexed
// lookup column and falling back to a table scan on an unauthenticated path)
// is worse than refusing to start.
func (s *Store) verifySchema() error {
	cols, err := s.tableColumns("api_keys")
	if err != nil {
		return err
	}
	if !cols["key_lookup"] {
		return errors.New("database predates the current schema (api_keys.key_lookup missing); delete it and re-enroll — pre-1.0, no migration path")
	}
	cols, err = s.tableColumns("pairings")
	if err != nil {
		return err
	}
	if !cols["code_salt"] {
		return errors.New("database predates the current schema (pairings.code_salt missing); delete it and re-enroll — pre-1.0, no migration path")
	}
	// machines.blocked carries the operator's soft block. The check is here
	// rather than left to a runtime error because CREATE TABLE IF NOT EXISTS
	// cannot add a column to a table that already exists: without this, an
	// older database fails on the first machineCols query with a raw
	// "no such column" instead of a message naming the column and the remedy.
	cols, err = s.tableColumns("machines")
	if err != nil {
		return err
	}
	if !cols["blocked"] {
		return errors.New("database predates the current schema (machines.blocked missing); run `ALTER TABLE machines ADD COLUMN blocked INTEGER DEFAULT 0` to keep this fleet, or delete the database and re-enroll — pre-1.0, no automatic migration")
	}
	if !cols["temporary"] {
		return errors.New("database predates the current schema (machines.temporary missing); run `ALTER TABLE machines ADD COLUMN temporary INTEGER DEFAULT 0` to keep this fleet, or delete the database and re-enroll — pre-1.0, no automatic migration")
	}
	return nil
}

func (s *Store) tableColumns(table string) (map[string]bool, error) {
	// SQLite answers from pragma_table_info; Postgres from information_schema.
	// Both report on the table the connection would actually use.
	q := `SELECT name FROM pragma_table_info(?)`
	if s.known == "postgres" {
		q = `SELECT column_name FROM information_schema.columns
			WHERE table_schema = current_schema() AND table_name = ?`
	}
	rows, err := s.query(q, table)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			return nil, err
		}
		out[name] = true
	}
	return out, rows.Err()
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

// RandToken returns a cryptographically random hex token.
func RandToken(nBytes int) string { return randHex(nBytes) }

// challengeAlphabet is Crockford-like: no I/L/O/0/1 to avoid transcription
// errors between a console screen and a phone keyboard.
const challengeAlphabet = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"

// ChallengeCodeLen: 12 chars over a 31-symbol alphabet ≈ 60 bits of
// entropy. Short numeric codes are disallowed: with the 5-attempt lockout
// the guessing probability per pairing is ~2^-58.
const ChallengeCodeLen = 12

// NormalizeCode is the canonical form of a challenge code: uppercase, with the
// display dashes and any spaces removed.
//
// It lives here, beside the hashing, because the two MUST agree, and they did
// not. NewChallengeCode returns the code dashed for display, CreatePairing hashed
// that dashed form, and the pair page normalized what the operator typed before
// comparing — so a correct code could never match, and every legitimate approval
// was counted as a wrong attempt (five of them expiring the pairing). The store's
// own tests passed the raw code straight from CreatePairing, and the server's
// tests exercised normalizeCode on its own; nothing covered the seam between
// them, which is where the bug lived.
//
// One function, used by both sides, is what stops that drifting again: anything
// that hashes or compares a code goes through it.
func NormalizeCode(s string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(s)) {
		if r == '-' || r == ' ' {
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// NewChallengeCode returns a human-typeable, high-entropy challenge code,
// formatted XXXX-XXXX-XXXX.
//
// The dashes are display only: what is hashed is the normalized form, so the
// operator may type the code with or without them.
func NewChallengeCode() string {
	b := make([]byte, ChallengeCodeLen)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	out := make([]byte, ChallengeCodeLen)
	for i, c := range b {
		out[i] = challengeAlphabet[int(c)%len(challengeAlphabet)]
	}
	s := string(out)
	return s[0:4] + "-" + s[4:8] + "-" + s[8:12]
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// PBKDF-lite: stretched SHA-256, iterated. For high-entropy keys a plain
// SHA-256 would suffice; the iteration exists so even a careless weak key
// resists offline cracking.
func stretch(key, salt string, iter int) string {
	h := sha256.Sum256([]byte(salt + "|" + key))
	sum := h[:]
	for i := 1; i < iter; i++ {
		h = sha256.Sum256(append(append([]byte{}, sum...), []byte(salt)...))
		sum = h[:]
	}
	return hex.EncodeToString(sum)
}

const stretchIter = 50_000

// HashSecret hashes a secret (API key or pairing code) under a salt.
func HashSecret(secret, salt string) string { return stretch(secret, salt, stretchIter) }

// HashKey is an alias kept for API-key call sites.
func HashKey(key, salt string) string { return HashSecret(key, salt) }

// LookupHash is the deterministic, unsalted digest used to find a row by a
// high-entropy secret in one indexed query.
//
// Salting and stretching exist to slow down guessing of *low-entropy*
// secrets. Pairing tokens are 256 bits and API keys 192 bits of CSPRNG
// output, so there is nothing to guess: what the salt bought us was a
// per-row hash of every candidate on every request, i.e. unbounded CPU work
// on unauthenticated endpoints proportional to table size. This makes the
// lookup O(1) while the stored secret remains unguessable.
//
// Low-entropy secrets (the 12-character pairing challenge code, which a human
// types) keep the salted, stretched hash via HashSecret.
func LookupHash(secret string) string {
	sum := sha256.Sum256([]byte("mach-lookup\x00" + secret))
	return hex.EncodeToString(sum[:])
}

// ValidOrgName enforces the org-prefix naming rule: "<org>-<machine>".
// Org: 2-20 chars; machine part: 1-48 chars; letters/digits/hyphen.
func ValidOrgName(org, name string) bool {
	if !validLabel(org, 2, 20) {
		return false
	}
	if !strings.HasPrefix(name, org+"-") {
		return false
	}
	return validLabel(strings.TrimPrefix(name, org+"-"), 1, 48)
}

func validLabel(s string, min, max int) bool {
	if len(s) < min || len(s) > max {
		return false
	}
	for _, c := range s {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

// ---- machines ----

type Machine struct {
	ID        int64
	Name      string
	PubKey    string
	Hostname  string
	OS        string
	Arch      string
	AgentVer  string
	CreatedAt string
	Revoked   bool
	PubE2E    string // X25519 public key (hex) for E2E exec encryption
	// Blocked is the operator's soft block: the agent stays connected and
	// keeps answering keepalives, but the control plane sends it no commands
	// and services no requests for it. Independent of Revoked — see
	// SetMachineBlocked.
	Blocked bool
	// Temporary marks an enrollment that belongs to a session rather than to a
	// machine: plain `mach` on a target, which keeps nothing on disk and revokes
	// itself on the way out. It is what lets that session be re-enrolled under
	// its own name without the operator revoking or deleting anything first —
	// including after a Ctrl-C that never got the chance to self-revoke, or a
	// power cut. A permanent enrollment clears it. See ReenrollMachine.
	Temporary bool
}

func (s *Store) CreateMachine(name, pubkey, hostname, os, arch, agentVer, pubE2E string, temporary bool) error {
	_, err := s.exec(`INSERT INTO machines (name, pubkey, hostname, os, arch, agent_version, created_at, pub_e2e, temporary)
		VALUES (?,?,?,?,?,?,?,?,?)`, name, pubkey, hostname, os, arch, agentVer, now(), pubE2E, boolInt(temporary))
	return err
}

// boolInt spells a bool the way every boolean column here is stored (INTEGER,
// scanned back with != 0), so the two drivers agree.
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

const machineCols = `id, name, pubkey, hostname, os, arch, agent_version, created_at, revoked, pub_e2e, blocked, temporary`

func scanMachine(row interface{ Scan(...any) error }) (*Machine, error) {
	m := &Machine{}
	var revoked, blocked, temporary int
	err := row.Scan(&m.ID, &m.Name, &m.PubKey, &m.Hostname, &m.OS, &m.Arch, &m.AgentVer, &m.CreatedAt, &revoked, &m.PubE2E, &blocked, &temporary)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.Revoked = revoked != 0
	m.Blocked = blocked != 0
	m.Temporary = temporary != 0
	return m, nil
}

func (s *Store) MachineByName(name string) (*Machine, error) {
	return scanMachine(s.queryRow(`SELECT `+machineCols+` FROM machines WHERE name = ?`, name))
}

func (s *Store) MachineByPubKey(pubkey string) (*Machine, error) {
	return scanMachine(s.queryRow(`SELECT `+machineCols+` FROM machines WHERE pubkey = ?`, pubkey))
}

func (s *Store) ListMachines() ([]Machine, error) {
	rows, err := s.query(`SELECT ` + machineCols + ` FROM machines ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Machine
	for rows.Next() {
		m, err := scanMachine(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *m)
	}
	return out, rows.Err()
}

// UpdateMachineMeta refreshes runtime metadata reported at agent connect.
func (s *Store) UpdateMachineMeta(id int64, hostname, os, arch, agentVer string) error {
	_, err := s.exec(`UPDATE machines SET hostname=?, os=?, arch=?, agent_version=? WHERE id=?`,
		hostname, os, arch, agentVer, id)
	return err
}

// RemoveMachine deletes an enrolled machine row by name.
func (s *Store) RemoveMachine(name string) error {
	_, err := s.exec(`DELETE FROM machines WHERE name=?`, name)
	return err
}

// RevokeMachine marks a machine revoked; agents self-retire on seeing it.
//
// Revocation is a forced re-enrollment, not a permanent ban: the row stays as the
// record (and so keeps the name and key reserved), the live agent is refused on
// reconnect, and enrolling again revives it — see ReactivateMachine. Deleting is
// the other path, and frees the name instead.
func (s *Store) RevokeMachine(name string) error {
	_, err := s.exec(`UPDATE machines SET revoked=1 WHERE name=?`, name)
	return err
}

// execer is the SQL surface the enrollment write needs, so the create-or-revive
// decision can run both inside ConsumePairing's transaction and outside one from
// the API-key path without duplicating its statement.
type execer interface {
	exec(q string, args ...any) (sql.Result, error)
}

// reenroll takes over an existing row for a new enrollment, re-keying it and
// clearing any revocation, and reports whether it actually matched one.
//
// Two conditions admit a takeover, and together they are the whole guard:
//
//   - REVOKED — revocation is a forced re-enrollment, so enrolling again is how
//     a revoked machine comes back. That is what makes revoke recoverable
//     without handing out the delete power.
//   - TEMPORARY — an enrollment that belongs to a session rather than to a
//     machine. Such a session revokes itself on the way out, but it may not get
//     the chance (a kill, a crash, a power cut), and the record it leaves must
//     not wedge its own name. This is what lets the next run reuse it without
//     the operator revoking or deleting anything first.
//
// Everything else is refused, and the guard is the WHERE clause rather than a
// check-then-write in Go: "never displace an active, permanent machine" has to
// hold against a race between a caller's existence check and this write, and
// only the SQL can promise that.
//
// The new enrollment states whether it is temporary, so it OVERWRITES the flag:
// re-enrolling a throwaway session permanently — `mach install` on a host that
// ran plain `mach` — records it as permanent, which is the point of recording it.
//
// blocked is deliberately left alone. It is an independent axis — neither block
// nor revoke writes the other's field — and a block left in place announces
// itself as a refusal that names the block, which is discoverable, where
// silently clearing an operator's block would not be.
func reenroll(ex execer, name, pubkey, hostname, os, arch, agentVer, pubE2E string, temporary bool) (bool, error) {
	res, err := ex.exec(`UPDATE machines
		SET pubkey=?, hostname=?, os=?, arch=?, agent_version=?, pub_e2e=?, revoked=0, temporary=?
		WHERE name=? AND (revoked=1 OR temporary=1)`,
		pubkey, hostname, os, arch, agentVer, pubE2E, boolInt(temporary), name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		// Both drivers report this, but a driver that could not means the caller
		// cannot tell "took over" from "no row to take over" — and guessing wrong
		// either skips the insert or duplicates the row.
		return false, err
	}
	return n > 0, nil
}

// ReenrollMachine takes over an existing machine row for a new enrollment —
// revoked or temporary only; see reenroll for why those two and nothing else.
// ok is false when no such row exists, in which case the caller inserts.
func (s *Store) ReenrollMachine(name, pubkey, hostname, os, arch, agentVer, pubE2E string, temporary bool) (bool, error) {
	return reenroll(s, name, pubkey, hostname, os, arch, agentVer, pubE2E, temporary)
}

// SetMachineBlocked sets or clears the operator's soft block on a machine.
// ok is false when no such machine exists, so callers report a 404 rather than
// a silent success.
//
// A block is a soft stop, not a retirement: the agent stays connected and keeps
// answering keepalives — it is simply sent no commands, and live console
// sessions for it are torn down. It is deliberately stored here rather than in
// the broker because it is operator-set state that has to survive a restart,
// and the broker survives nothing.
//
// revoked is left untouched in both directions: blocking a revoked machine, or
// clearing the block on one, must never change whether it is revoked. The two
// are independent axes — revoke is a permanent tombstone that keeps the name
// and key reserved, block is a reversible freeze on command dispatch.
//
// Note the two INSERTs into this table (CreateMachine, and the one inside
// ConsumePairing) deliberately do not name this column: DEFAULT 0 means a newly
// enrolled machine is never born blocked.
func (s *Store) SetMachineBlocked(name string, blocked bool) (ok bool, err error) {
	v := 0
	if blocked {
		v = 1
	}
	res, err := s.exec(`UPDATE machines SET blocked=? WHERE name=?`, v, name)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		// A driver that cannot report affected rows still wrote the value; the
		// caller's subsequent read is what decides, so report success.
		return true, nil
	}
	return n > 0, nil
}

// DeleteMachine removes a machine outright, freeing its name and its agent
// public key for re-enrollment.
//
// Revocation is the normal way to retire a machine: it keeps the row (and
// therefore any queued update, plus the fact that the key existed) while
// refusing the agent. Deleting is the recovery path for the case revocation
// cannot express — a machine that must enroll again from scratch, using the
// same name or even the same key material (a re-imaged box, a restored
// backup), where "already enrolled" would otherwise be a dead end.
//
// Audit rows are kept: who ran what on a machine is a record about the
// operator's fleet, not a property of the machine row. Purging it is a
// separate, explicit act (RemoveMachineAudit).
func (s *Store) DeleteMachine(name string) error {
	sqltx, err := s.db.Begin()
	if err != nil {
		return err
	}
	tx := &storeTx{tx: sqltx, s: s}
	defer sqltx.Rollback()
	if _, err := tx.exec(`DELETE FROM pending_updates WHERE machine=?`, name); err != nil {
		return err
	}
	if _, err := tx.exec(`DELETE FROM machines WHERE name=?`, name); err != nil {
		return err
	}
	return sqltx.Commit()
}

// ---- API keys ----

// Scopes: "exec:*" = all machines; "exec:<name>,<name>" = allowlist;
// "readonly" = machines + audit only; "enroll" = API-key enrollment only.
func (s *Store) CreateAPIKey(name, key, scopes string) error {
	salt := randHex(16)
	_, err := s.exec(`INSERT INTO api_keys (name, salt, key_lookup, key_hash, scopes, created_at) VALUES (?,?,?,?,?,?)`,
		name, salt, LookupHash(key), HashKey(key, salt), scopes, now())
	return err
}

// APIKeyExists resolves a bearer key in one indexed query. The indexed
// lookup hash is deterministic (see LookupHash); the stretched hash is then
// compared in constant time, so a caller cannot learn from timing how close
// a guess was.
func (s *Store) APIKeyExists(key string) (ok bool, keyName, scopes string, err error) {
	var name, salt, keyHash, scopesCol string
	var revoked int
	err = s.queryRow(`SELECT name, salt, key_hash, scopes, revoked FROM api_keys WHERE key_lookup = ?`,
		LookupHash(key)).Scan(&name, &salt, &keyHash, &scopesCol, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", "", nil
	}
	if err != nil {
		return false, "", "", err
	}
	if revoked != 0 {
		return false, "", "", nil
	}
	if subtle.ConstantTimeCompare([]byte(HashKey(key, salt)), []byte(keyHash)) != 1 {
		return false, "", "", nil
	}
	return true, name, scopesCol, nil
}

// APIKeyInfo is a key as an operator may see it: enough to recognise and reason
// about one, and nothing that helps guess or forge it.
//
// There is deliberately no field for salt, key_lookup or key_hash. key_lookup is
// the deterministic hash the bearer-key probe is indexed on — exposing it hands
// an attacker the value the server compares against — and key_hash is the
// stretched secret for offline cracking. The absence of the fields, rather than
// a promise not to fill them, is what keeps a future caller from leaking one.
type APIKeyInfo struct {
	Name      string
	Scopes    string
	CreatedAt string
	Revoked   bool
}

// ListAPIKeys returns every key's display metadata, ordered by name. It never
// selects a hash column.
func (s *Store) ListAPIKeys() ([]APIKeyInfo, error) {
	rows, err := s.query(`SELECT name, scopes, created_at, revoked FROM api_keys ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []APIKeyInfo
	for rows.Next() {
		var k APIKeyInfo
		var revoked int
		if err := rows.Scan(&k.Name, &k.Scopes, &k.CreatedAt, &revoked); err != nil {
			return nil, err
		}
		k.Revoked = revoked != 0
		out = append(out, k)
	}
	return out, rows.Err()
}

// ---- orgs ----

// Org is a configured org prefix. Pinned means it came from the environment
// (MACH_ORG / MACH_ORGS) and therefore cannot be removed from the UI — the same
// relationship MACH_E2E has to the stored E2E setting.
type Org struct {
	Name      string
	CreatedAt string
	CreatedBy string
	Pinned    bool
}

func (s *Store) CreateOrg(name, createdBy string) error {
	// Check first so the ordinary case gets a clean sentinel. The two engines
	// spell duplicate-key errors differently, and string-matching them would be
	// a Postgres bug waiting to happen. A genuine race between the check and the
	// insert still surfaces the driver's own error, which is the honest outcome
	// for an operator-driven action.
	exists, err := s.OrgExists(name)
	if err != nil {
		return err
	}
	if exists {
		return ErrOrgExists
	}
	_, err = s.exec(`INSERT INTO orgs (name, created_at, created_by) VALUES (?,?,?)`,
		name, now(), createdBy)
	return err
}

func (s *Store) DeleteOrg(name string) error {
	_, err := s.exec(`DELETE FROM orgs WHERE name=?`, name)
	return err
}

func (s *Store) OrgExists(name string) (bool, error) {
	var one int
	err := s.queryRow(`SELECT 1 FROM orgs WHERE name=?`, name).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}

// ListOrgsDB returns the orgs stored in the database, ordered by name. Pinned is
// never set here: the caller merges the environment in and marks those.
func (s *Store) ListOrgsDB() ([]Org, error) {
	rows, err := s.query(`SELECT name, created_at, created_by FROM orgs ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Org
	for rows.Next() {
		var o Org
		if err := rows.Scan(&o.Name, &o.CreatedAt, &o.CreatedBy); err != nil {
			return nil, err
		}
		out = append(out, o)
	}
	return out, rows.Err()
}

// ValidOrgLabel reports whether s is usable as an org prefix: 2-20 characters of
// letters, digits and hyphen.
//
// This is the org half of ValidOrgName, exported so the admin surfaces (the web
// UI's add-org form, the CLI) validate against the same rule the naming
// invariant uses rather than keeping their own copies that can drift.
func ValidOrgLabel(s string) bool { return validLabel(s, 2, 20) }

// ---- pairings ----

type Pairing struct {
	ID        string
	PubKey    string
	Hostname  string
	OS        string
	Arch      string
	AgentVer  string
	Name      string
	State     string
	CreatedAt string
	ExpiresAt string
	Consumed  bool
	Attempts  int
}

const pairingCols = `id, pubkey, hostname, os, arch, agent_version, name, state, created_at, expires_at, consumed, code_attempts`

func scanPairing(row interface{ Scan(...any) error }) (*Pairing, error) {
	p := &Pairing{}
	var consumed int
	err := row.Scan(&p.ID, &p.PubKey, &p.Hostname, &p.OS, &p.Arch, &p.AgentVer, &p.Name, &p.State,
		&p.CreatedAt, &p.ExpiresAt, &consumed, &p.Attempts)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Consumed = consumed != 0
	return p, nil
}

func (s *Store) CreatePairing(pubkey, hostname, os, arch, agentVer string, ttl time.Duration) (id, token, code string, err error) {
	id = randHex(8)
	token = randHex(32) // 256-bit one-time bearer token in the QR URL
	code = NewChallengeCode()
	codeSalt := randHex(16)
	_, err = s.exec(`INSERT INTO pairings (id, token_hash, pubkey, hostname, os, arch, agent_version, code_hash, code_salt, state, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)`,
		id, LookupHash(token), pubkey, hostname, os, arch, agentVer,
		HashSecret(NormalizeCode(code), codeSalt), codeSalt, now(),
		time.Now().UTC().Add(ttl).Format(time.RFC3339))
	return id, token, code, err
}

// PairingByToken resolves the one-time bearer token carried in the QR link.
// The token is a 256-bit random value, so it is matched by its deterministic
// hash (LookupHash) in a single indexed query rather than by hashing every
// candidate row: this lookup runs on unauthenticated endpoints, and its cost
// must not grow with the table.
//
// Any state, consumed or not: the agent poller has to see the state
// transition (expired/denied/approved), not a blind 404.
func (s *Store) PairingByToken(token string) (*Pairing, error) {
	var id string
	err := s.queryRow(`SELECT id FROM pairings WHERE token_hash = ?`, LookupHash(token)).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return s.pairingByID(id)
}

func (s *Store) pairingByID(id string) (*Pairing, error) {
	return scanPairing(s.queryRow(`SELECT `+pairingCols+` FROM pairings WHERE id = ?`, id))
}

// ExpireIfStale marks a pairing expired if past its expiry. Always re-reads
// state from the DB so callers see attempt-based expirations too.
func (s *Store) PairingState(p *Pairing) string {
	fresh, err := s.pairingByID(p.ID)
	if err == nil && fresh != nil {
		p.State = fresh.State
	}
	if p.State == "pending" {
		if exp, err := time.Parse(time.RFC3339, p.ExpiresAt); err == nil && time.Now().UTC().After(exp) {
			s.exec(`UPDATE pairings SET state='expired' WHERE id=? AND state='pending'`, p.ID)
			p.State = "expired"
		}
	}
	return p.State
}

// RecordPairingAttempt bumps the wrong-code counter. Returns false when the
// pairing has burned its attempts (auto-expire).
func (s *Store) RecordPairingAttempt(pairID string, max int) (ok bool, err error) {
	res, err := s.exec(`UPDATE pairings SET code_attempts = code_attempts + 1 WHERE id=?`, pairID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	var attempts int
	if err := s.queryRow(`SELECT code_attempts FROM pairings WHERE id=?`, pairID).Scan(&attempts); err != nil {
		return false, err
	}
	if attempts >= max {
		s.exec(`UPDATE pairings SET state='expired' WHERE id=? AND state='pending'`, pairID)
		return false, nil
	}
	return true, nil
}

func (s *Store) ApprovePairing(pairID, code, name string) (bool, string, error) {
	var codeHash, codeSalt, state string
	err := s.queryRow(`SELECT code_hash, code_salt, state FROM pairings WHERE id = ?`, pairID).Scan(&codeHash, &codeSalt, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "not found", nil
	}
	if err != nil {
		return false, "", err
	}
	if state != "pending" {
		return false, state, nil
	}
	if subtle.ConstantTimeCompare([]byte(HashSecret(NormalizeCode(code), codeSalt)), []byte(codeHash)) != 1 {
		return false, "bad-code", nil
	}
	// Guard on state: a concurrent DenyPairing must win over this approve —
	// never resurrect a denied pairing.
	res, err := s.exec(`UPDATE pairings SET state='approved', name=? WHERE id=? AND state='pending'`, name, pairID)
	if err != nil {
		return false, "", err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, "not-pending", nil
	}
	return true, "", nil
}

// DenyPairing transitions pending → denied. changed=false means the pairing
// was already in another state (the caller should re-read and show it).
func (s *Store) DenyPairing(pairID string) (changed bool, err error) {
	res, err := s.exec(`UPDATE pairings SET state='denied' WHERE id=? AND state='pending'`, pairID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// ConsumePairing atomically marks the pairing consumed (single use) and
// creates the machine in one transaction: if the machine insert fails
// (e.g. name UNIQUE conflict from two agents approved under the same name),
// the pairing stays un-consumed and claimable/inspectable instead of being
// permanently burned. Returns ok=false if it was already consumed or is no
// longer approved.
func (s *Store) ConsumePairing(p *Pairing, pubE2E string, temporary bool) (bool, error) {
	sqltx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	tx := &storeTx{tx: sqltx, s: s}
	defer sqltx.Rollback()
	res, err := tx.exec(`UPDATE pairings SET consumed=1 WHERE id=? AND consumed=0 AND state='approved'`, p.ID)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n == 0 {
		return false, nil
	}
	// Take over a revoked or temporary machine in place, or create a new one.
	// reenroll's WHERE clause is what enforces which rows may be taken over —
	// not a check in the caller.
	took, err := reenroll(tx, p.Name, p.PubKey, p.Hostname, p.OS, p.Arch, p.AgentVer, pubE2E, temporary)
	if err != nil {
		return false, err
	}
	if !took {
		if _, err := tx.exec(`INSERT INTO machines (name, pubkey, hostname, os, arch, agent_version, created_at, pub_e2e, temporary)
			VALUES (?,?,?,?,?,?,?,?,?)`, p.Name, p.PubKey, p.Hostname, p.OS, p.Arch, p.AgentVer, now(), pubE2E, boolInt(temporary)); err != nil {
			// consumed=1 rolls back with the transaction: the pairing survives
			// and the agent surfaces the error (usually a name conflict).
			return false, err
		}
	}
	return true, sqltx.Commit()
}

// CleanupExpiredPairings deletes terminal-state pairings older than maxAge.
// Approved-but-never-claimed pairings count as terminal after maxAge: they
// are claimable indefinitely otherwise.
//
// Pairings still marked pending are dropped once they are past their own
// expiry by more than maxAge. Nothing else ever clears them — a pending row
// whose agent gave up is never looked up again, so without this the table
// (which any unauthenticated caller can append to via pair-start) grows
// without bound.
func (s *Store) CleanupExpiredPairings(maxAge time.Duration) (int64, error) {
	nowT := time.Now().UTC()
	createdCutoff := nowT.Add(-maxAge).Format(time.RFC3339)
	expiryCutoff := nowT.Add(-maxAge).Format(time.RFC3339)
	res, err := s.exec(`DELETE FROM pairings
		WHERE (state IN ('expired','denied','approved') OR consumed=1) AND created_at < ?
		   OR (state = 'pending' AND expires_at < ?)`,
		createdCutoff, expiryCutoff)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// ---- audit ----

type AuditEntry struct {
	ID         int64
	TS         string
	Machine    string
	Command    string
	Source     string
	ExitCode   sql.NullInt64
	StdoutSnip string
	StderrSnip string
}

// snippet trims to a byte budget without splitting a UTF-8 rune, so audit
// rows never contain a mangled tail character.
func snippet(s string, n int) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) <= n {
		return s
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}

// RedactScrubs masks values next to secret-bearing keywords while keeping
// the keyword visible for audit readability. Everything from the separator
// to end of line after a keyword is masked (covers "password=x",
// "password: x", "Bearer xyz", multi-word tokens).
var secretPattern = regexp.MustCompile(`(?i)(password|passwd|secret|token|api[_-]?key|authorization|private key)\s*[=:]\s*([^'"\n]{0,1000})`)

func RedactScrubs(s string) string {
	s = strings.ReplaceAll(s, "\x00", "")
	return secretPattern.ReplaceAllString(s, "$1=[REDACTED]")
}

// Setting reads a control-plane setting. An absent key is not an error: it
// means "never set", and the caller's default applies.
func (s *Store) Setting(key string) (string, error) {
	var v string
	err := s.queryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&v)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return v, nil
}

// SetSetting writes a control-plane setting, replacing any previous value.
// The upsert is spelled the same way for both drivers (SQLite 3.24+ and
// Postgres agree on ON CONFLICT ... DO UPDATE).
func (s *Store) SetSetting(key, value string) error {
	_, err := s.exec(`INSERT INTO settings (key, value, updated_at) VALUES (?, ?, ?)
		ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`,
		key, value, now())
	return err
}

// DeleteSetting removes a setting so the caller's default applies again.
// Deleting an absent row is not an error: the caller asked for the same thing.
func (s *Store) DeleteSetting(key string) error {
	_, err := s.exec(`DELETE FROM settings WHERE key=?`, key)
	return err
}

// Settings returns every setting, for an operator-facing dump.
func (s *Store) Settings() (map[string]string, error) {
	rows, err := s.query(`SELECT key, value FROM settings`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return nil, err
		}
		out[k] = v
	}
	return out, rows.Err()
}

func (s *Store) AuditInsert(ts, machine, command, source string, exitCode sql.NullInt64, stdout, stderr string) error {
	_, err := s.exec(`INSERT INTO audit (ts, machine, command, source, exit_code, stdout_snip, stderr_snip)
		VALUES (?,?,?,?,?,?,?)`, ts, machine, snippet(RedactScrubs(command), 4096), source, exitCode,
		snippet(RedactScrubs(stdout), 4096), snippet(RedactScrubs(stderr), 4096))
	return err
}

func (s *Store) AuditList(machine string, limit int) ([]AuditEntry, error) {
	q := `SELECT id, ts, machine, command, source, exit_code, stdout_snip, stderr_snip FROM audit`
	var args []any
	if machine != "" && machine != "*" {
		q += ` WHERE machine = ?`
		args = append(args, machine)
	}
	q += ` ORDER BY id DESC LIMIT ?`
	args = append(args, limit)
	rows, err := s.query(q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AuditEntry
	for rows.Next() {
		var e AuditEntry
		if err := rows.Scan(&e.ID, &e.TS, &e.Machine, &e.Command, &e.Source, &e.ExitCode, &e.StdoutSnip, &e.StderrSnip); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// RemoveMachineAudit purges audit rows for a machine (revocation hygiene).
func (s *Store) RemoveMachineAudit(machine string) error {
	_, err := s.exec(`DELETE FROM audit WHERE machine=?`, machine)
	return err
}

// ---- pushed updates ----

// QueueUpdate stores a signed update manifest for a machine.
func (s *Store) QueueUpdate(machine, version, sha256Hex, url, dataB64, sigB64 string) error {
	_, err := s.exec(`INSERT INTO pending_updates (machine, version, sha256, url, data_b64, sig_b64, created_at)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT(machine) DO UPDATE SET
		version=excluded.version, sha256=excluded.sha256, url=excluded.url,
		data_b64=excluded.data_b64, sig_b64=excluded.sig_b64, created_at=excluded.created_at`,
		machine, version, sha256Hex, url, dataB64, sigB64, now())
	return err
}

// PopPendingUpdate returns and clears the queued update for a machine.
//
// One statement, deliberately: this used to be a SELECT followed by a separate
// DELETE, which was safe only while it had a single caller (the connect path).
// Delivering a held update on unblock is a second caller, and two concurrent
// pops of the same row would each have handed out the same signed manifest and
// then both reported success — the agent would apply one update twice. RETURNING
// collapses the read-and-clear into the statement that owns the row.
//
// It must go through queryRow (not exec, which discards rows) so that "nothing
// queued" stays the clean ErrNoRows -> ok=false, err=nil contract the callers
// depend on.
func (s *Store) PopPendingUpdate(machine string) (version, sha256Hex, url, dataB64, sigB64 string, ok bool, err error) {
	row := s.queryRow(`DELETE FROM pending_updates WHERE machine=?
		RETURNING version, sha256, url, data_b64, sig_b64`, machine)
	err = row.Scan(&version, &sha256Hex, &url, &dataB64, &sigB64)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", "", "", false, err
	}
	return version, sha256Hex, url, dataB64, sigB64, true, nil
}

// HasPendingUpdate reports whether an update is queued for a machine, without
// consuming it. Read-only counterpart to PopPendingUpdate, for callers that need
// to observe the queue rather than drain it.
func (s *Store) HasPendingUpdate(machine string) (bool, error) {
	var one int
	err := s.queryRow(`SELECT 1 FROM pending_updates WHERE machine=?`, machine).Scan(&one)
	if errors.Is(err, sql.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, nil
}
