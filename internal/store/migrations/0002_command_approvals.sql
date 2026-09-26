CREATE TABLE IF NOT EXISTS command_approvals (
	id {{ID}},
	machine TEXT NOT NULL,
	command TEXT NOT NULL,
	norm_key TEXT NOT NULL DEFAULT '',
	scope TEXT NOT NULL DEFAULT 'once',
	session TEXT DEFAULT '',
	requested_by TEXT DEFAULT '',
	created_at TEXT NOT NULL,
	status TEXT NOT NULL DEFAULT 'pending',
	expires_at TEXT DEFAULT ''
);
CREATE INDEX IF NOT EXISTS command_approvals_machine ON command_approvals(machine, status);
CREATE INDEX IF NOT EXISTS command_approvals_norm ON command_approvals(norm_key, status);