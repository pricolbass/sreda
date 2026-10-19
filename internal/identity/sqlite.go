package identity

import (
	"context"
	"database/sql"
	"errors"
)

// sqliteStore owns the SQL and transaction boundaries that preserve identity
// invariants across concurrent application instances. It is not a public seam.
type sqliteStore struct{ db *sql.DB }

func (s sqliteStore) createAdministrator(ctx context.Context, login string, hash []byte) (bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO users(login,password_hash,role) VALUES(?,?,'admin') ON CONFLICT(login) DO NOTHING`, login, hash)
	if err != nil {
		return false, err
	}
	count, err := result.RowsAffected()
	return count == 1, err
}
func (s sqliteStore) credentials(ctx context.Context, login string) (int64, []byte, error) {
	var id int64
	var hash []byte
	err := s.db.QueryRowContext(ctx, `SELECT id,password_hash FROM users WHERE login=?`, login).Scan(&id, &hash)
	return id, hash, err
}
func (s sqliteStore) rotateSession(ctx context.Context, id int64, hash []byte, old, next string, now, expiry int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at<=?`, now); err != nil {
		return err
	}
	if old != "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash(old)); err != nil {
			return err
		}
	}
	// Recheck the password inside the same write transaction as session creation.
	// A password reset that won the race must not be undone by a stale login.
	result, err := tx.ExecContext(ctx, `INSERT INTO sessions(token_hash,user_id,expires_at) SELECT ?,id,? FROM users WHERE id=? AND password_hash=?`, tokenHash(next), expiry, id, hash)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return InvalidCredentials
	}
	return tx.Commit()
}
func (s sqliteStore) sessionUser(ctx context.Context, token string, now int64) (User, error) {
	var user User
	err := s.db.QueryRowContext(ctx, `SELECT users.id,users.login,users.role FROM sessions JOIN users ON users.id=sessions.user_id WHERE sessions.token_hash=? AND sessions.expires_at>?`, tokenHash(token), now).Scan(&user.ID, &user.Login, &user.Role)
	return user, err
}
func (s sqliteStore) userRole(ctx context.Context, id int64) (string, error) {
	var role string
	err := s.db.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, id).Scan(&role)
	return role, err
}
func (s sqliteStore) deleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE token_hash=?`, tokenHash(token))
	return err
}
func (s sqliteStore) resetAdministrator(ctx context.Context, login string, hash []byte) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE login=? AND role='admin'`, hash, login)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return AdministratorNotFound
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id IN(SELECT id FROM users WHERE login=? AND role='admin')`, login); err != nil {
		return err
	}
	return tx.Commit()
}

type invitationRecord struct {
	id, expiry      int64
	used, cancelled bool
}

func (s sqliteStore) invitations(ctx context.Context) ([]invitationRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,expires_at,cancelled_at,used_at FROM invitations ORDER BY id DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []invitationRecord
	for rows.Next() {
		var item invitationRecord
		var cancelled, used sql.NullInt64
		if err := rows.Scan(&item.id, &item.expiry, &cancelled, &used); err != nil {
			return nil, err
		}
		item.cancelled = cancelled.Valid
		item.used = used.Valid
		result = append(result, item)
	}
	return result, rows.Err()
}
func (s sqliteStore) issueInvitation(ctx context.Context, actorID int64, token string, expiry int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO invitations(token_hash,created_by,expires_at) VALUES(?,?,?)`, tokenHash(token), actorID, expiry)
	return err
}
func (s sqliteStore) cancelInvitation(ctx context.Context, id, now int64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE invitations SET cancelled_at=? WHERE id=? AND used_at IS NULL AND cancelled_at IS NULL AND expires_at>?`, now, id, now)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return InvitationConflict
	}
	return nil
}
func (s sqliteStore) invitationExpiry(ctx context.Context, token string, now int64) (int64, error) {
	var expiry int64
	err := s.db.QueryRowContext(ctx, `SELECT expires_at FROM invitations WHERE token_hash=? AND expires_at>? AND used_at IS NULL AND cancelled_at IS NULL`, tokenHash(token), now).Scan(&expiry)
	return expiry, err
}
func (s sqliteStore) acceptInvitation(ctx context.Context, token, login string, hash []byte, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Claim before inserting; any collision/error rolls back the claim.
	result, err := tx.ExecContext(ctx, `UPDATE invitations SET used_at=? WHERE token_hash=? AND expires_at>? AND used_at IS NULL AND cancelled_at IS NULL`, now, tokenHash(token), now)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return InvitationInactive
	}
	result, err = tx.ExecContext(ctx, `INSERT INTO users(login,password_hash,role) VALUES(?,?,'user') ON CONFLICT(login) DO NOTHING`, login, hash)
	if err != nil {
		return err
	}
	count, err = result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return LoginTaken
	}
	return tx.Commit()
}
func (s sqliteStore) ordinaryUsers(ctx context.Context) ([]User, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,login FROM users WHERE role='user' ORDER BY login`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []User
	for rows.Next() {
		var user User
		if err := rows.Scan(&user.ID, &user.Login); err != nil {
			return nil, err
		}
		user.Role = "user"
		result = append(result, user)
	}
	return result, rows.Err()
}
func (s sqliteStore) issueRecovery(ctx context.Context, userID int64, token string, expiry int64) error {
	result, err := s.db.ExecContext(ctx, `INSERT INTO password_recovery(user_id,token_hash,expires_at) SELECT id,?,? FROM users WHERE id=? AND role='user' ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at,used_at=NULL`, tokenHash(token), expiry, userID)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return UserNotFound
	}
	return nil
}
func (s sqliteStore) recoveryExpiry(ctx context.Context, token string, now int64) (int64, error) {
	var expiry int64
	err := s.db.QueryRowContext(ctx, `SELECT expires_at FROM password_recovery JOIN users ON users.id=password_recovery.user_id WHERE token_hash=? AND expires_at>? AND used_at IS NULL AND role='user'`, tokenHash(token), now).Scan(&expiry)
	return expiry, err
}
func (s sqliteStore) applyRecovery(ctx context.Context, token string, hash []byte, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var userID int64
	err = tx.QueryRowContext(ctx, `UPDATE password_recovery SET used_at=? WHERE token_hash=? AND expires_at>? AND used_at IS NULL AND user_id IN(SELECT id FROM users WHERE role='user') RETURNING user_id`, now, tokenHash(token), now).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return RecoveryInactive
	}
	if err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET password_hash=? WHERE id=? AND role='user'`, hash, userID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}
