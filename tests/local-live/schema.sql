CREATE TABLE users(id TEXT PRIMARY KEY,full_name TEXT NOT NULL,normalized_name TEXT UNIQUE NOT NULL,access_key_hash TEXT NOT NULL,is_active INTEGER NOT NULL CHECK(is_active IN(0,1)));
CREATE TABLE projects(id TEXT PRIMARY KEY,name TEXT NOT NULL);
CREATE TABLE project_members(project_id TEXT NOT NULL,user_id TEXT NOT NULL,role TEXT NOT NULL,PRIMARY KEY(project_id,user_id));
CREATE TABLE user_sessions(id TEXT PRIMARY KEY,user_id TEXT NOT NULL,token_hash TEXT UNIQUE NOT NULL,expires_at TEXT NOT NULL,revoked_at TEXT);
CREATE TABLE auth_login_limits(client_key TEXT PRIMARY KEY,window_minute INTEGER,attempts INTEGER);
CREATE TABLE conversations(id TEXT PRIMARY KEY,user_name TEXT,created_at TEXT,updated_at TEXT,project_id TEXT,created_by_user_id TEXT,title TEXT,is_archived INTEGER DEFAULT 0);
CREATE TABLE messages(id INTEGER PRIMARY KEY AUTOINCREMENT,conversation_id TEXT,role TEXT,content TEXT,created_at TEXT,sender_user_id TEXT);
