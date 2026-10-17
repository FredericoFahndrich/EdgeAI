-- Records the Firebase account generation after a live lookup. No users or memberships change.
CREATE TABLE IF NOT EXISTS edgeai_firebase_account_origins (
  firebase_project TEXT NOT NULL CHECK(firebase_project='edgeai-auth'),
  firebase_uid TEXT NOT NULL,
  created_at_ms TEXT NOT NULL,
  first_checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(firebase_project,firebase_uid),
  FOREIGN KEY(firebase_project,firebase_uid)
    REFERENCES edgeai_firebase_identities(firebase_project,firebase_uid) ON DELETE RESTRICT
);
INSERT OR IGNORE INTO edgeai_schema_migrations(version) VALUES('0004_firebase_account_origins');
