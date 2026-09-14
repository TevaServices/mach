package store

// Versioned schema migrations. The DDL lives in migrations/*.sql (embedded),
// each file one numbered step; the runner below applies any this binary has
// that the database does not, and refuses to start against a database whose
// history disagrees with it.
//
// The pre-migration world had no version table at all: an existing database
// is adopted at the baseline if verifySchema accepts it, and refused with the
// same message it would always have given otherwise.

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

// migration is one embedded step. version is the filename minus .sql; the
// leading NNNN is the sequence that orders application. The checksum is the
// sha256 of the raw file bytes: it is stamped into schema_migrations at
// apply time and re-verified on every open, so an applied migration that is
// edited later — or a database someone hand-tinkered with — is a loud
// startup failure rather than a silently divergent schema.
type migration struct {
	version  string
	filename string
	sql      string
	sha256   string
}

// migrationSet holds the embedded migrations, sorted by sequence. The runner
// reads it on every migrate() call rather than caching it, so tests can swap
// in a synthetic set.
var migrationSet = loadMigrations()

// migrationName pins the file-naming rule: a 4-digit zero-padded sequence,
// an underscore, and a lowercase name. The version recorded in the database
// is the filename, so a rename would look like a different migration.
var migrationName = regexp.MustCompile(`^[0-9]{4}_[a-z0-9_]+$`)

func loadMigrations() []migration {
	entries, err := migrationsFS.ReadDir("migrations")
	if err != nil {
		panic("store: embedded migrations unreadable: " + err.Error())
	}
	var out []migration
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		version := strings.TrimSuffix(name, ".sql")
		if !strings.HasSuffix(name, ".sql") || !migrationName.MatchString(version) {
			continue
		}
		data, err := migrationsFS.ReadFile("migrations/" + name)
		if err != nil {
			panic("store: embedded migration " + name + " unreadable: " + err.Error())
		}
		out = append(out, migration{
			version:  version,
			filename: name,
			sql:      string(data),
			sha256:   sha256Hex(data),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].filename < out[j].filename })
	return out
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// schemaMigrationsSQL is the version table itself, created before anything
// runs. It is written in the same {{ID}} style as the rest of the schema so
// the two drivers share it.
const schemaMigrationsSQL = `CREATE TABLE IF NOT EXISTS schema_migrations (
	id {{ID}},
	version TEXT NOT NULL UNIQUE,
	checksum TEXT NOT NULL,
	applied_at TEXT NOT NULL
)`

// pgMigrationLockKey serializes concurrent opens on the Postgres path: two
// control planes starting at once must not race to apply the same migration.
// SQLite needs no equivalent — its pool is capped at one connection, and a
// BEGIN IMMEDIATE takes the write lock on the file.
const pgMigrationLockKey = 0x6d616368 // "mach"

func (s *Store) migrate() error {
	if _, err := s.exec(strings.ReplaceAll(schemaMigrationsSQL, "{{ID}}", s.idColumn())); err != nil {
		return fmt.Errorf("create schema_migrations: %w", err)
	}
	applied, err := s.appliedMigrations()
	if err != nil {
		return err
	}
	if len(applied) == 0 {
		mcols, err := s.tableColumns("machines")
		if err != nil {
			return err
		}
		if len(mcols) > 0 {
			// A database from before migrations existed. verifySchema's
			// refusal messages are preserved verbatim: a stale schema is
			// still refused exactly as it always was, and only a database
			// this binary would have accepted is adopted, stamped at the
			// baseline (which is the migration that creates that schema).
			if err := s.verifySchema(); err != nil {
				return err
			}
			if len(migrationSet) == 0 {
				return errors.New("cannot adopt a pre-migration database: no migrations are embedded in this binary")
			}
			base := migrationSet[0]
			if err := insertMigrationRow(s, base); err != nil {
				return err
			}
			applied[base.version] = base.sha256
			log.Printf("store: adopted existing database at baseline %s", base.version)
		}
	}

	// An applied version still embedded here must checksum-match: history
	// was edited after the fact (here or on disk) otherwise.
	for _, m := range migrationSet {
		if have, ok := applied[m.version]; ok && have != m.sha256 {
			return fmt.Errorf("schema migration %s has been modified since it was applied (checksum mismatch; applied %s, embedded %s)", m.version, have, m.sha256)
		}
	}

	maxApplied, maxVersion := 0, ""
	for v := range applied {
		seq, err := migrationSeq(v)
		if err != nil {
			return fmt.Errorf("applied migration %q: %w", v, err)
		}
		if seq > maxApplied {
			maxApplied, maxVersion = seq, v
		}
		// A row naming a migration this binary does not embed is unknown
		// history even when its sequence does not exceed the binary's head:
		// a renamed, renumbered or hand-inserted step would otherwise be
		// silently tolerated, and the checksum check above never sees it.
		known := false
		for _, m := range migrationSet {
			if m.version == v {
				known = true
				break
			}
		}
		if !known {
			return fmt.Errorf("database records migration %s, which this binary does not have; upgrade mach or restore a backup", v)
		}
	}
	maxEmbedded := 0
	for _, m := range migrationSet {
		seq, err := migrationSeq(m.version)
		if err != nil {
			return fmt.Errorf("embedded migration %s: %w", m.filename, err)
		}
		if seq > maxEmbedded {
			maxEmbedded = seq
		}
	}
	if maxApplied > maxEmbedded {
		return fmt.Errorf("database schema is newer than this binary (migration %s is applied); upgrade mach or restore a backup", maxVersion)
	}
	for _, m := range migrationSet {
		seq, err := migrationSeq(m.version)
		if err != nil {
			return err // already reported above; kept for the loop below
		}
		if _, ok := applied[m.version]; !ok && seq < maxApplied {
			return fmt.Errorf("migration history is inconsistent: %s is embedded but missing from schema_migrations while %s is applied", m.version, maxVersion)
		}
	}

	for _, m := range migrationSet {
		seq, err := migrationSeq(m.version)
		if err != nil {
			return err
		}
		if _, ok := applied[m.version]; ok || seq <= maxApplied {
			continue
		}
		if err := s.applyMigration(m); err != nil {
			return fmt.Errorf("migration %s (<migrations/%s>) failed: %w", m.version, m.filename, err)
		}
		log.Printf("store: applied migration %s", m.version)
	}
	return nil
}

// migrationSeq extracts a migration's sequence number from its version
// (the leading 4 digits of "NNNN_name").
func migrationSeq(version string) (int, error) {
	if len(version) < 5 || version[4] != '_' {
		return 0, fmt.Errorf("version %q does not follow NNNN_name", version)
	}
	seqStr := version[:4]
	for i := 0; i < 4; i++ {
		if seqStr[i] < '0' || seqStr[i] > '9' {
			return 0, fmt.Errorf("version %q does not start with a 4-digit sequence", version)
		}
	}
	n, err := strconv.Atoi(seqStr)
	if err != nil {
		return 0, err
	}
	return n, nil
}

func (s *Store) appliedMigrations() (map[string]string, error) {
	rows, err := s.query(`SELECT version, checksum FROM schema_migrations`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var v, c string
		if err := rows.Scan(&v, &c); err != nil {
			return nil, err
		}
		out[v] = c
	}
	return out, rows.Err()
}

func insertMigrationRow(ex execer, m migration) error {
	_, err := ex.exec(`INSERT INTO schema_migrations (version, checksum, applied_at) VALUES (?,?,?)`,
		m.version, m.sha256, now())
	return err
}

// applyMigration runs one migration and records it, in one transaction. The
// DDL is the whole file content, {{ID}}-substituted and rebind-translated
// like every other statement in this package; both drivers accept a
// multi-statement Exec.
func (s *Store) applyMigration(m migration) error {
	body := strings.ReplaceAll(m.sql, "{{ID}}", s.idColumn())
	if s.known == "postgres" {
		tx, err := s.db.Begin()
		if err != nil {
			return err
		}
		defer tx.Rollback()
		t := &storeTx{tx: tx, s: s}
		if _, err := t.exec(`SELECT pg_advisory_xact_lock(?)`, pgMigrationLockKey); err != nil {
			return err
		}
		if _, err := t.exec(body); err != nil {
			return err
		}
		if err := insertMigrationRow(t, m); err != nil {
			return err
		}
		return tx.Commit()
	}
	// SQLite: the pool holds exactly one connection, so the raw BEGIN below
	// pins the transaction to the connection every subsequent statement in
	// this block is handed — they all share it, and a failure rolls the
	// whole step back.
	if _, err := s.db.Exec("BEGIN IMMEDIATE"); err != nil {
		return err
	}
	if _, err := s.exec(body); err != nil {
		s.db.Exec("ROLLBACK")
		return err
	}
	if err := insertMigrationRow(s, m); err != nil {
		s.db.Exec("ROLLBACK")
		return err
	}
	if _, err := s.db.Exec("COMMIT"); err != nil {
		s.db.Exec("ROLLBACK")
		return err
	}
	return nil
}
