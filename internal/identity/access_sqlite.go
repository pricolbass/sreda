package identity

import (
	"context"
	"database/sql"
	"errors"
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
func (s sqliteStore) block(ctx context.Context, actorID, userID, revision int64) (AccountAccess, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return AccountAccess{}, err
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, actorID).Scan(&role); err != nil || role != "admin" {
		return AccountAccess{}, Forbidden
	}
	var a AccountAccess
	err = tx.QueryRowContext(ctx, `SELECT id,login,blocked,access_revision,access_state,access_error FROM users WHERE id=? AND role='user'`, userID).Scan(&a.ID, &a.Login, &a.Blocked, &a.Revision, &a.State, &a.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return a, UserNotFound
	}
	if err != nil {
		return a, err
	}
	if a.Revision != revision {
		return a, AccessConflict
	}
	if !a.Blocked {
		a.Revision++
	}
	a.Blocked = true
	a.State = "Отключение выполняется"
	a.Error = ""
	if _, err = tx.ExecContext(ctx, `UPDATE users SET blocked=1,access_revision=?,access_state=?,access_error='' WHERE id=?`, a.Revision, a.State, userID); err != nil {
		return a, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		return a, err
	}
	return a, tx.Commit()
}
func (s sqliteStore) finishBlock(ctx context.Context, id, revision int64, problem string) error {
	state := "Доступ закрыт"
	if problem != "" {
		state = "Ошибка закрытия доступа"
	}
	result, err := s.db.ExecContext(ctx, `UPDATE users SET access_state=?,access_error=? WHERE id=? AND blocked=1 AND access_revision=?`, state, problem, id, revision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return AccessConflict
	}
	return err
}
func (s sqliteStore) unblock(ctx context.Context, actorID, id, revision int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var role string
	if err := tx.QueryRowContext(ctx, `SELECT role FROM users WHERE id=?`, actorID).Scan(&role); err != nil || role != "admin" {
		return Forbidden
	}
	var blocked bool
	var rev int64
	var state string
	err = tx.QueryRowContext(ctx, `SELECT blocked,access_revision,access_state FROM users WHERE id=? AND role='user'`, id).Scan(&blocked, &rev, &state)
	if errors.Is(err, sql.ErrNoRows) {
		return UserNotFound
	}
	if err != nil {
		return err
	}
	if revision != rev {
		return AccessConflict
	}
	if !blocked {
		return nil
	}
	if state != "Доступ закрыт" {
		return AccessIncomplete
	}
	if _, err := tx.ExecContext(ctx, `UPDATE users SET blocked=0,access_revision=access_revision+1,access_state='Вход разрешён',access_error='' WHERE id=?`, id); err != nil {
		return err
	}
	return tx.Commit()
}
