package identity

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s sqliteStore) accountAccess(ctx context.Context) ([]AccountAccess, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,login,blocked,access_revision,access_state,access_error FROM users WHERE role='user' ORDER BY login`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountAccess
	for rows.Next() {
		var a AccountAccess
		if err := rows.Scan(&a.ID, &a.Login, &a.Blocked, &a.Revision, &a.State, &a.Error); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s sqliteStore) block(ctx context.Context, actorID, userID int64, decide func(accountAccessCandidate) (AccountAccess, error)) (AccountAccess, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccountAccess{}, err
	}
	defer tx.Rollback()
	candidate, err := readAccountAccess(ctx, tx, actorID, userID)
	if err != nil {
		return AccountAccess{}, err
	}
	a, err := decide(candidate)
	if err != nil {
		return a, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE users SET blocked=1,access_revision=?,access_state=?,access_error='' WHERE id=?`, a.Revision, a.State, userID); err != nil {
		return a, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return a, err
	}
	return a, tx.Commit()
}
func (s sqliteStore) finishBlock(ctx context.Context, id, revision int64, lease, state, problem string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE users SET access_state=?,access_error=? WHERE id=? AND blocked=1 AND access_revision=? AND EXISTS(SELECT 1 FROM user_closures c WHERE c.user_id=users.id AND c.lease_owner=? AND c.revision=? AND c.lease_until>?)`, state, problem, id, revision, lease, revision, time.Now().Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return AccessConflict
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM user_closures WHERE user_id=? AND lease_owner=?`, id, lease); err != nil {
		return err
	}
	return tx.Commit()
}
func (s sqliteStore) unblock(ctx context.Context, actorID, id int64, decide func(accountAccessCandidate) (accountAccessDecision, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	candidate, err := readAccountAccess(ctx, tx, actorID, id)
	if err != nil {
		return err
	}
	decision, err := decide(candidate)
	if err != nil || !decision.Change {
		return err
	}
	a := decision.Account
	if _, err := tx.ExecContext(ctx, `UPDATE users SET blocked=?,access_revision=?,access_state=?,access_error=? WHERE id=?`, a.Blocked, a.Revision, a.State, a.Error, id); err != nil {
		return err
	}
	return tx.Commit()
}

func readAccountAccess(ctx context.Context, tx *sql.Tx, actorID, id int64) (accountAccessCandidate, error) {
	var candidate accountAccessCandidate
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, actorID).Scan(&candidate.ActorRole); err != nil {
		return candidate, nil
	}
	a := &candidate.Account
	err := tx.QueryRowContext(ctx, `SELECT id,login,blocked,access_revision,access_state,access_error FROM users WHERE id=? AND role='user'`, id).Scan(&a.ID, &a.Login, &a.Blocked, &a.Revision, &a.State, &a.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return candidate, nil
	}
	return candidate, err
}

// InstallClosureSchema stores only workflow ownership, never authentication secrets.
func InstallClosureSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS user_closures(user_id INTEGER PRIMARY KEY REFERENCES users(id),revision INTEGER NOT NULL,lease_owner TEXT NOT NULL,lease_until INTEGER NOT NULL); CREATE TABLE IF NOT EXISTS user_closure_attempts(user_id INTEGER PRIMARY KEY REFERENCES users(id),last_attempt INTEGER NOT NULL);`)
	return err
}
func (s sqliteStore) pendingClosures(ctx context.Context) ([]AccountAccess, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT u.id,u.access_revision FROM users u LEFT JOIN user_closure_attempts a ON a.user_id=u.id WHERE u.blocked=1 AND u.access_state<>'Доступ закрыт' AND NOT EXISTS(SELECT 1 FROM user_closures c WHERE c.user_id=u.id AND c.lease_until>?) ORDER BY COALESCE(a.last_attempt,0),u.id`, time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AccountAccess
	for rows.Next() {
		var a AccountAccess
		if err := rows.Scan(&a.ID, &a.Revision); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}
func (s sqliteStore) claimClosure(ctx context.Context, id, revision int64, lease string) (string, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var eligible bool
	err = tx.QueryRowContext(ctx, `SELECT blocked=1 AND access_revision=? AND access_state<>'Доступ закрыт' FROM users WHERE id=?`, revision, id).Scan(&eligible)
	if err != nil {
		return "", err
	}
	if !eligible {
		return "", nil
	}
	now := time.Now().Unix()
	var live bool
	if err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM user_closures WHERE user_id=? AND lease_until>?)`, id, now).Scan(&live); err != nil {
		return "", err
	}
	if live {
		return "", AccessIncomplete
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_closures(user_id,revision,lease_owner,lease_until)VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET revision=excluded.revision,lease_owner=excluded.lease_owner,lease_until=excluded.lease_until`, id, revision, lease, now+90); err != nil {
		return "", err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO user_closure_attempts(user_id,last_attempt) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET last_attempt=excluded.last_attempt`, id, time.Now().UnixNano()); err != nil {
		return "", err
	}
	return lease, tx.Commit()
}
