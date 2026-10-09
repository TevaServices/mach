-- The secrets registry: which secret NAMES each org's machines hold.
--
-- Values never reach the control plane — they live in each agent's local
-- store, and pushes travel sealed. What the control plane keeps is the
-- namespace: enough to refuse an injection whose name belongs to another
-- org before dispatching, to answer "what does this machine hold" without
-- polling it, and to give an org's admins a record of what was provisioned
-- to their fleet. A name is not a secret; the registry is metadata by
-- construction (there is no value column to leak).
--
-- last_seen_at tracks the freshest evidence that the machine still holds
-- the name (an announce or a successful push), so a stale row is visible as
-- such rather than silently authoritative.

CREATE TABLE IF NOT EXISTS secrets (
	org TEXT NOT NULL,
	name TEXT NOT NULL,
	created_at TEXT NOT NULL,
	created_by TEXT DEFAULT '',
	last_seen_at TEXT NOT NULL DEFAULT '',
	PRIMARY KEY (org, name)
);
CREATE INDEX IF NOT EXISTS secrets_org ON secrets(org);
