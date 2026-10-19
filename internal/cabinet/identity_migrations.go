package cabinet

import "database/sql"

// Rebuilding users also rebuilds its foreign-key dependent sessions. Copying
// them first preserves active v1 sessions without ALTER TABLE rename rewriting
// their foreign keys to a temporary table.
func migrateInvitations(tx *sql.Tx) error {
	_, err := tx.Exec(`
 CREATE TABLE users_new (id INTEGER PRIMARY KEY, login TEXT NOT NULL UNIQUE, password_hash BLOB NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')));
 INSERT INTO users_new SELECT id,login,password_hash,role FROM users;
 CREATE TEMP TABLE sessions_backup AS SELECT * FROM sessions;
 DROP TABLE sessions;
 DROP TABLE users;
 ALTER TABLE users_new RENAME TO users;
 CREATE TABLE sessions (token_hash BLOB PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
 INSERT INTO sessions SELECT * FROM sessions_backup;
 DROP TABLE sessions_backup;
 CREATE INDEX sessions_expiry ON sessions(expires_at);
 CREATE TABLE invitations (id INTEGER PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE, created_by INTEGER NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL, cancelled_at INTEGER, used_at INTEGER);
 PRAGMA user_version=2;
 `)
	return err
}

func installPasswordRecovery(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE password_recovery(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,token_hash BLOB NOT NULL UNIQUE,expires_at INTEGER NOT NULL,used_at INTEGER); PRAGMA user_version=3;`)
	return err
}
