-- Additive: never rename users, replace identities or grant memberships.
-- Reservations survive suspension/revocation. Email changes require reviewed migration.
CREATE TABLE IF NOT EXISTS edgeai_identity_emails (
  email TEXT PRIMARY KEY COLLATE NOCASE,
  user_id TEXT NOT NULL UNIQUE REFERENCES users(id) ON DELETE RESTRICT,
  firebase_uid TEXT UNIQUE,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
INSERT OR IGNORE INTO edgeai_identity_emails(email,user_id,firebase_uid)
  SELECT lower(trim(email)),user_id,claimed_uid FROM edgeai_email_approvals;
-- Prevent a concurrent administrative approval from reserving an auto-created email.
CREATE TRIGGER IF NOT EXISTS edgeai_approval_email_guard
BEFORE INSERT ON edgeai_email_approvals
WHEN EXISTS(SELECT 1 FROM edgeai_identity_emails WHERE email=NEW.email OR user_id=NEW.user_id)
BEGIN SELECT RAISE(ABORT,'identity email reserved'); END;
CREATE TRIGGER IF NOT EXISTS edgeai_approval_email_reserve
AFTER INSERT ON edgeai_email_approvals
BEGIN
  INSERT INTO edgeai_identity_emails(email,user_id,firebase_uid)
    VALUES(lower(trim(NEW.email)),NEW.user_id,NEW.claimed_uid);
END;
CREATE TABLE IF NOT EXISTS edgeai_personal_documents (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE RESTRICT,
  file_name TEXT NOT NULL,
  object_key TEXT NOT NULL UNIQUE,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL CHECK(size_bytes>0),
  uploaded_by_user_id TEXT NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_edgeai_personal_documents ON edgeai_personal_documents(user_id,created_at DESC);
INSERT OR IGNORE INTO edgeai_schema_migrations(version) VALUES('0003_verified_self_registration');
