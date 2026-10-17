-- Existing users, identities and memberships are preserved.
CREATE TABLE IF NOT EXISTS edgeai_email_approvals (
  email TEXT PRIMARY KEY COLLATE NOCASE,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
  approved_by TEXT NOT NULL REFERENCES users(id),
  approved_at TEXT NOT NULL,
  revoked_at TEXT,
  claimed_uid TEXT,
  claimed_at TEXT
);
CREATE TABLE IF NOT EXISTS edgeai_admin_audit (
  id TEXT PRIMARY KEY,
  actor_user_id TEXT NOT NULL REFERENCES users(id),
  action TEXT NOT NULL,
  target_user_id TEXT NOT NULL REFERENCES users(id),
  detail TEXT NOT NULL,
  created_at TEXT NOT NULL
);
INSERT OR IGNORE INTO edgeai_schema_migrations(version) VALUES('0002_email_access_admin');
