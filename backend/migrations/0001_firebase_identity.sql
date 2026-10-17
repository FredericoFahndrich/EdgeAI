-- Additive migration. No identity is inferred from a name or email.
CREATE TABLE IF NOT EXISTS edgeai_firebase_identities (
  firebase_project TEXT NOT NULL CHECK(firebase_project = 'edgeai-auth'),
  firebase_uid TEXT NOT NULL CHECK(length(firebase_uid) BETWEEN 1 AND 128),
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
  approved_by TEXT NOT NULL,
  approved_at TEXT NOT NULL,
  revoked_at TEXT,
  PRIMARY KEY(firebase_project, firebase_uid)
);
CREATE TABLE IF NOT EXISTS edgeai_firebase_sessions (
  session_id TEXT PRIMARY KEY REFERENCES user_sessions(id) ON DELETE CASCADE,
  firebase_project TEXT NOT NULL,
  firebase_uid TEXT NOT NULL,
  FOREIGN KEY(firebase_project, firebase_uid)
    REFERENCES edgeai_firebase_identities(firebase_project, firebase_uid)
);
CREATE TABLE IF NOT EXISTS edgeai_schema_migrations (
  version TEXT PRIMARY KEY, applied_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO edgeai_schema_migrations(version) VALUES('0001_firebase_identity');
