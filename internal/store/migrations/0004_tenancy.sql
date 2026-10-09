-- Tenancy: the org becomes the tenant boundary, not a naming convention.
--
-- Up to this migration an org existed only as the prefix of a machine's
-- globally-unique name, re-derived at runtime by matching configured org
-- lists against that prefix. That made an org mutable by configuration: an
-- org removed from the environment silently changed which tenant every one
-- of its machines belonged to, and no principal — API key, UI identity,
-- approval, audit row — carried any org at all. The columns below record the
-- org as a stored fact on every row a tenant can see or own, written by the
-- same code that enforces the naming invariant, so there is one source of
-- truth for "which tenant does this belong to".
--
-- '' is the deliberate sentinel for rows written before this migration. A
-- server backfills it once at startup (BackfillMachineOrgs) from the name
-- prefixes; anything left '' belongs to no configured org and is visible to
-- no tenant, which is the fail-closed direction.

ALTER TABLE machines ADD COLUMN org TEXT NOT NULL DEFAULT '';
ALTER TABLE api_keys ADD COLUMN org TEXT NOT NULL DEFAULT '';
ALTER TABLE audit ADD COLUMN org TEXT NOT NULL DEFAULT '';
ALTER TABLE command_approvals ADD COLUMN org TEXT NOT NULL DEFAULT '';
ALTER TABLE pairings ADD COLUMN org TEXT NOT NULL DEFAULT '';

-- A machine's identity within its org. names stay globally unique (the
-- canonical "<org>-<machine>" string remains the storage key and the whole
-- dispatch path's identifier — see store.MachineByName), so this index is
-- redundant with machines.name's uniqueness until a later migration makes
-- local names the identifiers. It exists now so the tenancy model, not an
-- accident of the canonical string, is what enforces per-org namespace
-- uniqueness when that change comes.
CREATE UNIQUE INDEX IF NOT EXISTS machines_org_name ON machines(org, name);

-- Which tenant a machine belongs to, for org-scoped reads.
CREATE INDEX IF NOT EXISTS machines_org ON machines(org);

-- Org-scoped audit reads and approvals listing.
CREATE INDEX IF NOT EXISTS audit_org_ts ON audit(org, id);
CREATE INDEX IF NOT EXISTS command_approvals_org ON command_approvals(org, status);

-- UI membership: who may act on which org, and how much. One row per
-- (org, email). A member of the superadmin role is stored once with org '*'
-- and governs every org, including org management itself — the CLI remains
-- the unauthenticated bootstrap path, but the UI's own authorization no
-- longer rests on "anyone the issuer verifies".
-- Roles: superadmin | admin | operator | viewer (validated in Go; a CHECK
-- would be the second home of a rule the store code also needs).
CREATE TABLE IF NOT EXISTS ui_members (
	id {{ID}},
	org TEXT NOT NULL DEFAULT '*',
	email TEXT NOT NULL,
	subject TEXT DEFAULT '',
	role TEXT NOT NULL,
	created_at TEXT NOT NULL,
	created_by TEXT DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS ui_members_org_email ON ui_members(org, email);
CREATE INDEX IF NOT EXISTS ui_members_email ON ui_members(email);
