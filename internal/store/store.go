// Package store implements the control plane's persistence: machines,
// API keys, pairing sessions, and the command audit log, in SQLite
// (pure-Go driver, single file, WAL mode).
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
	"strings"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	_ "modernc.org/sqlite"
)

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
	return s, nil
}

// Known reports the backing driver ("sqlite" or "postgres").
func (s *Store) Known() string { return s.known }

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate() error {
	_, err := s.db.Exec(`
CREATE TABLE IF NOT EXISTS machines (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL UNIQUE,
	pubkey TEXT NOT NULL UNIQUE,
	hostname TEXT DEFAULT '',
	os TEXT DEFAULT '',
	arch TEXT DEFAULT '',
	agent_version TEXT DEFAULT '',
	created_at TEXT NOT NULL,
	revoked INTEGER DEFAULT 0,
	pub_e2e TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS api_keys (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	salt TEXT NOT NULL,
	key_hash TEXT NOT NULL UNIQUE,
	scopes TEXT NOT NULL DEFAULT 'exec:*',
	created_at TEXT NOT NULL,
	revoked INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS pairings (
	id TEXT PRIMARY KEY,
	token_hash TEXT NOT NULL UNIQUE,
	pubkey TEXT NOT NULL,
	hostname TEXT DEFAULT '',
	os TEXT DEFAULT '',
	arch TEXT DEFAULT '',
	agent_version TEXT DEFAULT '',
	code_hash TEXT NOT NULL,
	code_salt TEXT NOT NULL,
	code_attempts INTEGER DEFAULT 0,
	name TEXT DEFAULT '',
	state TEXT NOT NULL DEFAULT 'pending',
	created_at TEXT NOT NULL,
	expires_at TEXT NOT NULL,
	consumed INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS audit (
	id INTEGER PRIMARY KEY,
	ts TEXT NOT NULL,
	machine TEXT NOT NULL,
	command TEXT NOT NULL,
	source TEXT NOT NULL,
	exit_code INTEGER,
	stdout_snip TEXT DEFAULT '',
	stderr_snip TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS audit_machine_ts ON audit(machine, ts);
CREATE TABLE IF NOT EXISTS pending_updates (
	machine TEXT PRIMARY KEY,
	version TEXT NOT NULL,
	sha256 TEXT NOT NULL,
	url TEXT DEFAULT '',
	data_b64 TEXT DEFAULT '',
	sig_b64 TEXT NOT NULL,
	created_at TEXT NOT NULL
);
`)
	return err
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

// NewChallengeCode returns a human-typeable, high-entropy challenge code,
// formatted XXXX-XXXX-XXXX.
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
}

func (s *Store) CreateMachine(name, pubkey, hostname, os, arch, agentVer, pubE2E string) error {
	_, err := s.db.Exec(`INSERT INTO machines (name, pubkey, hostname, os, arch, agent_version, created_at, pub_e2e)
		VALUES (?,?,?,?,?,?,?,?)`, name, pubkey, hostname, os, arch, agentVer, now(), pubE2E)
	return err
}

const machineCols = `id, name, pubkey, hostname, os, arch, agent_version, created_at, revoked, pub_e2e`

func scanMachine(row interface{ Scan(...any) error }) (*Machine, error) {
	m := &Machine{}
	var revoked int
	err := row.Scan(&m.ID, &m.Name, &m.PubKey, &m.Hostname, &m.OS, &m.Arch, &m.AgentVer, &m.CreatedAt, &revoked, &m.PubE2E)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	m.Revoked = revoked != 0
	return m, nil
}

func (s *Store) MachineByName(name string) (*Machine, error) {
	return scanMachine(s.db.QueryRow(`SELECT `+machineCols+` FROM machines WHERE name = ?`, name))
}

func (s *Store) MachineByPubKey(pubkey string) (*Machine, error) {
	return scanMachine(s.db.QueryRow(`SELECT `+machineCols+` FROM machines WHERE pubkey = ?`, pubkey))
}

func (s *Store) ListMachines() ([]Machine, error) {
	rows, err := s.db.Query(`SELECT ` + machineCols + ` FROM machines ORDER BY name`)
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
	_, err := s.db.Exec(`UPDATE machines SET hostname=?, os=?, arch=?, agent_version=? WHERE id=?`,
		hostname, os, arch, agentVer, id)
	return err
}

// RemoveMachine deletes an enrolled machine row by name.
func (s *Store) RemoveMachine(name string) error {
	_, err := s.db.Exec(`DELETE FROM machines WHERE name=?`, name)
	return err
}

// RevokeMachine marks a machine revoked; agents self-retire on seeing it.
func (s *Store) RevokeMachine(name string) error {
	_, err := s.db.Exec(`UPDATE machines SET revoked=1 WHERE name=?`, name)
	return err
}

// ---- API keys ----

// Scopes: "exec:*" = all machines; "exec:<name>,<name>" = allowlist;
// "readonly" = machines + audit only; "enroll" = API-key enrollment only.
func (s *Store) CreateAPIKey(name, key, scopes string) error {
	salt := randHex(16)
	_, err := s.db.Exec(`INSERT INTO api_keys (name, salt, key_hash, scopes, created_at) VALUES (?,?,?,?,?)`,
		name, salt, HashKey(key, salt), scopes, now())
	return err
}

func (s *Store) APIKeyExists(key string) (ok bool, keyName, scopes string, err error) {
	rows, err := s.db.Query(`SELECT name, salt, key_hash, scopes, revoked FROM api_keys`)
	if err != nil {
		return false, "", "", err
	}
	defer rows.Close()
	for rows.Next() {
		var name, salt, keyHash, scopes string
		var revoked int
		if err := rows.Scan(&name, &salt, &keyHash, &scopes, &revoked); err != nil {
			return false, "", "", err
		}
		if revoked != 0 {
			continue
		}
		if subtle.ConstantTimeCompare([]byte(HashKey(key, salt)), []byte(keyHash)) == 1 {
			return true, name, scopes, nil
		}
	}
	return false, "", "", rows.Err()
}

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
	_, err = s.db.Exec(`INSERT INTO pairings (id, token_hash, pubkey, hostname, os, arch, agent_version, code_hash, code_salt, state, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)`,
		id, HashKey(token, codeSalt), pubkey, hostname, os, arch, agentVer,
		HashSecret(code, codeSalt), codeSalt, now(),
		time.Now().UTC().Add(ttl).Format(time.RFC3339))
	return id, token, code, err
}

// pairingScanCap bounds how many candidate pairings a token lookup hashes
// (most recent first). Each candidate costs a 50k-iteration stretched hash,
// and this lookup runs on unauthenticated endpoints — the cap keeps the
// per-request work constant instead of scaling with table size. Live
// pairings are short-lived (pending TTL is minutes; approved-but-unclaimed
// rows are cleaned up after a day), so 64 comfortably covers real traffic.
const pairingScanCap = 64

func (s *Store) PairingByToken(token string) (*Pairing, error) {
	// Tokens are hashed under each pairing's own salt; one pass computes the
	// candidate hash per live (non-consumed) pairing and constant-time
	// compares. Non-consumed of any state: the agent poller must see the
	// state transition (expired/denied), not a blind 404.
	rows, err := s.db.Query(`SELECT id, code_salt, token_hash FROM pairings WHERE consumed=0 ORDER BY created_at DESC LIMIT ?`, pairingScanCap)
	if err != nil {
		return nil, err
	}
	type cand struct{ id, salt, tokHash string }
	var cands []cand
	for rows.Next() {
		var c cand
		if err := rows.Scan(&c.id, &c.salt, &c.tokHash); err != nil {
			rows.Close()
			return nil, err
		}
		cands = append(cands, c)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for _, c := range cands {
		if subtle.ConstantTimeCompare([]byte(HashKey(token, c.salt)), []byte(c.tokHash)) == 1 {
			return s.pairingByID(c.id)
		}
	}
	return nil, nil
}

func (s *Store) pairingByID(id string) (*Pairing, error) {
	return scanPairing(s.db.QueryRow(`SELECT `+pairingCols+` FROM pairings WHERE id = ?`, id))
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
			s.db.Exec(`UPDATE pairings SET state='expired' WHERE id=? AND state='pending'`, p.ID)
			p.State = "expired"
		}
	}
	return p.State
}

// RecordPairingAttempt bumps the wrong-code counter. Returns false when the
// pairing has burned its attempts (auto-expire).
func (s *Store) RecordPairingAttempt(pairID string, max int) (ok bool, err error) {
	res, err := s.db.Exec(`UPDATE pairings SET code_attempts = code_attempts + 1 WHERE id=?`, pairID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	var attempts int
	if err := s.db.QueryRow(`SELECT code_attempts FROM pairings WHERE id=?`, pairID).Scan(&attempts); err != nil {
		return false, err
	}
	if attempts >= max {
		s.db.Exec(`UPDATE pairings SET state='expired' WHERE id=? AND state='pending'`, pairID)
		return false, nil
	}
	return true, nil
}

func (s *Store) ApprovePairing(pairID, code, name string) (bool, string, error) {
	var codeHash, codeSalt, state string
	err := s.db.QueryRow(`SELECT code_hash, code_salt, state FROM pairings WHERE id = ?`, pairID).Scan(&codeHash, &codeSalt, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "not found", nil
	}
	if err != nil {
		return false, "", err
	}
	if state != "pending" {
		return false, state, nil
	}
	if subtle.ConstantTimeCompare([]byte(HashSecret(code, codeSalt)), []byte(codeHash)) != 1 {
		return false, "bad-code", nil
	}
	// Guard on state: a concurrent DenyPairing must win over this approve —
	// never resurrect a denied pairing.
	res, err := s.db.Exec(`UPDATE pairings SET state='approved', name=? WHERE id=? AND state='pending'`, name, pairID)
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
	res, err := s.db.Exec(`UPDATE pairings SET state='denied' WHERE id=? AND state='pending'`, pairID)
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
func (s *Store) ConsumePairing(p *Pairing, pubE2E string) (bool, error) {
	tx, err := s.db.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	res, err := tx.Exec(`UPDATE pairings SET consumed=1 WHERE id=? AND consumed=0 AND state='approved'`, p.ID)
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
	if _, err := tx.Exec(`INSERT INTO machines (name, pubkey, hostname, os, arch, agent_version, created_at, pub_e2e)
		VALUES (?,?,?,?,?,?,?,?)`, p.Name, p.PubKey, p.Hostname, p.OS, p.Arch, p.AgentVer, now(), pubE2E); err != nil {
		// consumed=1 rolls back with the transaction: the pairing survives
		// and the agent surfaces the error (usually a name conflict).
		return false, err
	}
	return true, tx.Commit()
}

// CleanupExpiredPairings deletes terminal-state pairings older than maxAge.
// Approved-but-never-claimed pairings count as terminal after maxAge: they
// are claimable indefinitely otherwise, and their token lookup cost is paid
// on every unauthenticated pair-page request.
func (s *Store) CleanupExpiredPairings(maxAge time.Duration) (int64, error) {
	cutoff := time.Now().UTC().Add(-maxAge).Format(time.RFC3339)
	res, err := s.db.Exec(`DELETE FROM pairings WHERE (state IN ('expired','denied','approved') OR consumed=1) AND created_at < ?`, cutoff)
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

func snippet(s string, n int) string {
	s = strings.ReplaceAll(s, "\x00", "")
	if len(s) > n {
		return s[:n]
	}
	return s
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

func (s *Store) AuditInsert(ts, machine, command, source string, exitCode sql.NullInt64, stdout, stderr string) error {
	_, err := s.db.Exec(`INSERT INTO audit (ts, machine, command, source, exit_code, stdout_snip, stderr_snip)
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
	rows, err := s.db.Query(q, args...)
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
	_, err := s.db.Exec(`DELETE FROM audit WHERE machine=?`, machine)
	return err
}

// ---- pushed updates ----

// QueueUpdate stores a signed update manifest for a machine.
func (s *Store) QueueUpdate(machine, version, sha256Hex, url, dataB64, sigB64 string) error {
	_, err := s.db.Exec(`INSERT INTO pending_updates (machine, version, sha256, url, data_b64, sig_b64, created_at)
		VALUES (?,?,?,?,?,?,?) ON CONFLICT(machine) DO UPDATE SET
		version=excluded.version, sha256=excluded.sha256, url=excluded.url,
		data_b64=excluded.data_b64, sig_b64=excluded.sig_b64, created_at=excluded.created_at`,
		machine, version, sha256Hex, url, dataB64, sigB64, now())
	return err
}

// PendingUpdate returns and clears the queued update for a machine.
func (s *Store) PopPendingUpdate(machine string) (version, sha256Hex, url, dataB64, sigB64 string, ok bool, err error) {
	row := s.db.QueryRow(`SELECT version, sha256, url, data_b64, sig_b64 FROM pending_updates WHERE machine=?`, machine)
	err = row.Scan(&version, &sha256Hex, &url, &dataB64, &sigB64)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", "", "", "", false, nil
	}
	if err != nil {
		return "", "", "", "", "", false, err
	}
	// Clear after successful handoff (agent acks by reconnecting with the
	// new version; a failed apply re-pushes on next admin command).
	_, err = s.db.Exec(`DELETE FROM pending_updates WHERE machine=?`, machine)
	return version, sha256Hex, url, dataB64, sigB64, err == nil, err
}
