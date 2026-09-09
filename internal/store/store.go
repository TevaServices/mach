// Package store implements the control plane's persistence: machines,
// API keys, pairing sessions, and the command audit log, in SQLite
// (pure-Go driver, single file, WAL mode).
package store

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

type Store struct {
	db *sql.DB
}

func Open(path string) (*Store, error) {
	dsn := fmt.Sprintf("file:%s?_pragma=busy_timeout(5000)&_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)", path)
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

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
	created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS api_keys (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	key_hash TEXT NOT NULL UNIQUE,
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
	code TEXT NOT NULL,
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

// NewPairingCode returns the human challenge code: 6 digits, no leading zero
// ambiguity beyond what rand gives us (compare exactly, so any digits are fine).
func NewPairingCode() string {
	b := make([]byte, 3)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", int(b[0])<<16|int(b[1])<<8|int(b[2]))
}

func now() string { return time.Now().UTC().Format(time.RFC3339) }

// ---- machines ----

type Machine struct {
	ID          int64
	Name        string
	PubKey      string
	Hostname    string
	OS          string
	Arch        string
	AgentVer    string
	CreatedAt   string
}

func (s *Store) CreateMachine(name, pubkey, hostname, os, arch, agentVer string) error {
	_, err := s.db.Exec(`INSERT INTO machines (name, pubkey, hostname, os, arch, agent_version, created_at)
		VALUES (?,?,?,?,?,?,?)`, name, pubkey, hostname, os, arch, agentVer, now())
	return err
}

func (s *Store) MachineByName(name string) (*Machine, error) {
	m := &Machine{}
	err := s.db.QueryRow(`SELECT id, name, pubkey, hostname, os, arch, agent_version, created_at
		FROM machines WHERE name = ?`, name).
		Scan(&m.ID, &m.Name, &m.PubKey, &m.Hostname, &m.OS, &m.Arch, &m.AgentVer, &m.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Store) MachineByPubKey(pubkey string) (*Machine, error) {
	m := &Machine{}
	err := s.db.QueryRow(`SELECT id, name, pubkey, hostname, os, arch, agent_version, created_at
		FROM machines WHERE pubkey = ?`, pubkey).
		Scan(&m.ID, &m.Name, &m.PubKey, &m.Hostname, &m.OS, &m.Arch, &m.AgentVer, &m.CreatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return m, nil
}

func (s *Store) ListMachines() ([]Machine, error) {
	rows, err := s.db.Query(`SELECT id, name, pubkey, hostname, os, arch, agent_version, created_at
		FROM machines ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Machine
	for rows.Next() {
		var m Machine
		if err := rows.Scan(&m.ID, &m.Name, &m.PubKey, &m.Hostname, &m.OS, &m.Arch, &m.AgentVer, &m.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// UpdateMachineMeta refreshes runtime metadata reported at agent connect.
func (s *Store) UpdateMachineMeta(id int64, hostname, os, arch, agentVer string) error {
	_, err := s.db.Exec(`UPDATE machines SET hostname=?, os=?, arch=?, agent_version=? WHERE id=?`,
		hostname, os, arch, agentVer, id)
	return err
}

// RemoveMachine deletes an enrolled machine by name.
func (s *Store) RemoveMachine(name string) error {
	_, err := s.db.Exec(`DELETE FROM machines WHERE name=?`, name)
	return err
}

// ---- API keys ----

// HashKey derives a deterministic internal lookup hash. (API keys are
// high-entropy random values; a plain SHA-256 is an appropriate store-at-rest
// form — no password stretching needed.)
func HashKey(key string) string {
	sum := sha256sum(key)
	return sum
}

func (s *Store) CreateAPIKey(name, key string) error {
	_, err := s.db.Exec(`INSERT INTO api_keys (name, key_hash, created_at) VALUES (?,?,?)`,
		name, HashKey(key), now())
	return err
}

func (s *Store) APIKeyExists(key string) (bool, string, error) {
	row := s.db.QueryRow(`SELECT name, revoked FROM api_keys WHERE key_hash = ?`, HashKey(key))
	var name string
	var revoked int
	err := row.Scan(&name, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	if err != nil {
		return false, "", err
	}
	if revoked != 0 {
		return false, name, nil
	}
	return true, name, nil
}

// ---- pairings ----

type Pairing struct {
	ID          string
	PubKey      string
	Hostname    string
	OS          string
	Arch        string
	AgentVer    string
	Code        string
	Name        string
	State       string
	CreatedAt   string
	ExpiresAt   string
	Consumed    bool
}

func (s *Store) CreatePairing(pubkey, hostname, os, arch, agentVer, code, name string, ttl time.Duration) (id, token string, err error) {
	id = randHex(8)
	token = randHex(16)
	_, err = s.db.Exec(`INSERT INTO pairings (id, token_hash, pubkey, hostname, os, arch, agent_version, code, name, state, created_at, expires_at)
		VALUES (?,?,?,?,?,?,?,?,?,'pending',?,?)`,
		id, HashKey(token), pubkey, hostname, os, arch, agentVer, code, name, now(),
		time.Now().UTC().Add(ttl).Format(time.RFC3339))
	return id, token, err
}

func (s *Store) PairingByToken(token string) (*Pairing, error) {
	p := &Pairing{}
	var consumed int
	err := s.db.QueryRow(`SELECT id, pubkey, hostname, os, arch, agent_version, code, name, state, created_at, expires_at, consumed
		FROM pairings WHERE token_hash = ?`, HashKey(token)).
		Scan(&p.ID, &p.PubKey, &p.Hostname, &p.OS, &p.Arch, &p.AgentVer, &p.Code, &p.Name, &p.State, &p.CreatedAt, &p.ExpiresAt, &consumed)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	p.Consumed = consumed != 0
	return p, nil
}

// ExpireIfStale marks a pairing expired if past its expiry. Returns updated state.
func (s *Store) PairingState(p *Pairing) string {
	if p.State == "pending" {
		if exp, err := time.Parse(time.RFC3339, p.ExpiresAt); err == nil && time.Now().UTC().After(exp) {
			s.db.Exec(`UPDATE pairings SET state='expired' WHERE id=?`, p.ID)
			p.State = "expired"
		}
	}
	return p.State
}

func (s *Store) ApprovePairing(pairID, code, name string) (bool, string, error) {
	// Verify the challenge code matches before approving.
	var storedCode string
	var state string
	err := s.db.QueryRow(`SELECT code, state FROM pairings WHERE id = ?`, pairID).Scan(&storedCode, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "not found", nil
	}
	if err != nil {
		return false, "", err
	}
	if state != "pending" {
		return false, state, nil
	}
	if strings.TrimSpace(code) != storedCode {
		return false, "bad-code", nil
	}
	_, err = s.db.Exec(`UPDATE pairings SET state='approved', name=? WHERE id=?`, name, pairID)
	return err == nil, "", err
}

func (s *Store) DenyPairing(pairID string) error {
	_, err := s.db.Exec(`UPDATE pairings SET state='denied' WHERE id=? AND state='pending'`, pairID)
	return err
}

// ReopenPairing returns an approved pairing to pending (used when the
// proposed name was invalid so the approver can retry).
func (s *Store) ReopenPairing(pairID string) error {
	_, err := s.db.Exec(`UPDATE pairings SET state='pending' WHERE id=? AND state='approved'`, pairID)
	return err
}

// ConsumePairing atomically marks the pairing consumed (single use) and
// creates the machine. Returns ok=false if it was already consumed.
func (s *Store) ConsumePairing(p *Pairing) (bool, error) {
	res, err := s.db.Exec(`UPDATE pairings SET consumed=1 WHERE id=? AND consumed=0`, p.ID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return false, nil
	}
	return true, s.CreateMachine(p.Name, p.PubKey, p.Hostname, p.OS, p.Arch, p.AgentVer)
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

func (s *Store) AuditInsert(ts, machine, command, source string, exitCode sql.NullInt64, stdout, stderr string) error {
	_, err := s.db.Exec(`INSERT INTO audit (ts, machine, command, source, exit_code, stdout_snip, stderr_snip)
		VALUES (?,?,?,?,?,?,?)`, ts, machine, command, source, exitCode, snippet(stdout, 4096), snippet(stderr, 4096))
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