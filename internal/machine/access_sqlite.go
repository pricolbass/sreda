package machine

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *sqliteStore) reserveConnectionOperation(ctx context.Context, id int64, enabled bool, owner string, now time.Time, requireEnabled bool) (connectionOperation, error) {
	op := connectionOperation{owner: owner, enabled: enabled}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op, err
	}
	defer tx.Rollback()
	var deleting bool
	err = tx.QueryRowContext(ctx, `SELECT id,owner_id,COALESCE(public_key,''),COALESCE(tunnel_address,''),enabled,EXISTS(SELECT 1 FROM machine_deletions WHERE machine_id=machines.id) FROM machines WHERE id=?`, id).Scan(&op.connection.ID, &op.connection.OwnerID, &op.connection.PublicKey, &op.connection.Address, &op.connection.Enabled, &deleting)
	if errors.Is(err, sql.ErrNoRows) {
		return op, failure(NotFound, "Машина не найдена")
	}
	if err != nil {
		return op, err
	}
	if requireEnabled && (deleting || !op.connection.Enabled) {
		return connectionOperation{}, nil
	}
	if deleting {
		return op, failure(Invalid, "Машина уже удаляется")
	}
	if op.connection.PublicKey == "" {
		return op, failure(Invalid, "Машина ещё не подключена")
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM machine_connection_ops WHERE machine_id=?", id).Scan(&count); err != nil {
		return op, err
	}
	if count != 0 {
		return op, failure(Unavailable, "Предыдущее изменение подключения ещё ожидает очистки")
	}
	if _, err = tx.ExecContext(ctx, "UPDATE machines SET enabled=0 WHERE id=?", id); err != nil {
		return op, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO machine_connection_ops(machine_id,desired_enabled,phase,lease_owner,lease_until) VALUES(?,?,'working',?,?)", id, enabled, owner, now.Add(enrollmentLease).Unix()); err != nil {
		return op, err
	}
	return op, tx.Commit()
}
func (s *sqliteStore) finishConnectionOperation(ctx context.Context, op connectionOperation) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE machines SET enabled=? WHERE id=? AND NOT EXISTS(SELECT 1 FROM machine_deletions WHERE machine_id=machines.id) AND EXISTS(SELECT 1 FROM machine_connection_ops WHERE machine_id=machines.id AND lease_owner=? AND phase='working' AND lease_until>?)`, op.enabled, op.connection.ID, op.owner, time.Now().Unix())
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return failure(Unavailable, "Устаревшее изменение подключения отменено")
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM machine_connection_ops WHERE machine_id=? AND lease_owner=?", op.connection.ID, op.owner); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *sqliteStore) markConnectionCleanup(ctx context.Context, op connectionOperation) error {
	result, err := s.db.ExecContext(ctx, "UPDATE machine_connection_ops SET phase='cleanup' WHERE machine_id=? AND lease_owner=?", op.connection.ID, op.owner)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return failure(Unavailable, "Очистку подключения выполняет другой процесс")
	}
	return nil
}
func (s *sqliteStore) finishConnectionCleanup(ctx context.Context, op connectionOperation) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM machine_connection_ops WHERE machine_id=? AND lease_owner=? AND phase='cleanup'", op.connection.ID, op.owner)
	return err
}
func (s *sqliteStore) releaseConnectionCleanup(ctx context.Context, op connectionOperation) error {
	_, err := s.db.ExecContext(ctx, "UPDATE machine_connection_ops SET lease_owner='',lease_until=0,phase='cleanup' WHERE machine_id=? AND lease_owner=?", op.connection.ID, op.owner)
	return err
}
func (s *sqliteStore) claimConnectionCleanup(ctx context.Context, owner string, now time.Time) ([]connectionOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT o.machine_id,COALESCE(m.public_key,''),COALESCE(m.tunnel_address,'') FROM machine_connection_ops o JOIN machines m ON m.id=o.machine_id WHERE o.lease_until<=? ORDER BY o.machine_id LIMIT 2`, now.Unix())
	if err != nil {
		return nil, err
	}
	var operations []connectionOperation
	for rows.Next() {
		op := connectionOperation{owner: owner}
		if err = rows.Scan(&op.connection.ID, &op.connection.PublicKey, &op.connection.Address); err != nil {
			rows.Close()
			return nil, err
		}
		operations = append(operations, op)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, op := range operations {
		if _, err = tx.ExecContext(ctx, "UPDATE machine_connection_ops SET phase='cleanup',lease_owner=?,lease_until=? WHERE machine_id=?", owner, now.Add(enrollmentLease).Unix(), op.connection.ID); err != nil {
			return nil, err
		}
	}
	return operations, tx.Commit()
}
