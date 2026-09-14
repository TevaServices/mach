CREATE TABLE IF NOT EXISTS machines (
	id {{ID}},
	name TEXT NOT NULL UNIQUE,
	pubkey TEXT NOT NULL UNIQUE,
	hostname TEXT DEFAULT '',
	os TEXT DEFAULT '',
	arch TEXT DEFAULT '',
	agent_version TEXT DEFAULT '',
	created_at TEXT NOT NULL,
	revoked INTEGER DEFAULT 0,
	pub_e2e TEXT DEFAULT '',
	blocked INTEGER DEFAULT 0,
	temporary INTEGER DEFAULT 0
);
CREATE TABLE IF NOT EXISTS api_keys (
	id {{ID}},
	name TEXT NOT NULL,
	salt TEXT NOT NULL,
	key_lookup TEXT NOT NULL UNIQUE,
	key_hash TEXT NOT NULL,
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
	id {{ID}},
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
CREATE TABLE IF NOT EXISTS settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS orgs (
	name TEXT PRIMARY KEY,
	created_at TEXT NOT NULL,
	created_by TEXT DEFAULT ''
);
