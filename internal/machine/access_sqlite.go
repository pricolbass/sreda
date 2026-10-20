package machine

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *sqliteStore) reserveConnectionOperation(ctx context.Context, id int64, enabled bool, owner string, now time.Time, preserveEnabled bool, decide func(connectionCandidate) (connectionDecision, error)) (connectionOperation, error) {
	op := connectionOperation{owner: owner, enabled: enabled}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return op, err
	}
	defer tx.Rollback()
	var deleting, blocked, desired bool
	err = tx.QueryRowContext(ctx, `SELECT id,owner_id,COALESCE(public_key,''),COALESCE(tunnel_address,''),enabled,desired_enabled,access_revision,(SELECT access_revision FROM users WHERE id=machines.owner_id),(SELECT blocked FROM users WHERE id=machines.owner_id),EXISTS(SELECT 1 FROM machine_deletions WHERE machine_id=machines.id) FROM machines WHERE id=?`, id).Scan(&op.connection.ID, &op.connection.OwnerID, &op.connection.PublicKey, &op.connection.Address, &op.connection.Enabled, &desired, &op.connection.Revision, &op.connection.OwnerRevision, &blocked, &deleting)
	if errors.Is(err, sql.ErrNoRows) {
		return op, failure(NotFound, "Машина не найдена")
	}
	if err != nil {
		return op, err
	}
	candidate := connectionCandidate{Connection: op.connection, Deleting: deleting, OwnerBlocked: blocked, DesiredEnabled: desired}
	if err = tx.QueryRowContext(ctx, "SELECT EXISTS(SELECT 1 FROM machine_reconnections WHERE machine_id=?),EXISTS(SELECT 1 FROM machine_connection_ops WHERE machine_id=?)", id, id).Scan(&candidate.Replacing, &candidate.OperationPending); err != nil {
		return op, err
	}
	decision, err := decide(candidate)
	if err != nil {
		return op, err
	}
	if !decision.Change {
		return connectionOperation{}, nil
	}
	if decision.AdvanceRevision {
		op.connection.Revision++
		if _, err := tx.ExecContext(ctx, "UPDATE machines SET access_revision=? WHERE id=?", op.connection.Revision, id); err != nil {
			return op, err
		}
	}
	if _, err = tx.ExecContext(ctx, "UPDATE machines SET enabled=CASE WHEN ? THEN enabled ELSE 0 END,desired_enabled=?,access_state=?,access_error='' WHERE id=?", preserveEnabled, enabled, decision.State, id); err != nil {
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
	result, err := tx.ExecContext(ctx, `UPDATE machines SET enabled=?,access_state=?,access_error='' WHERE id=? AND access_revision=? AND desired_enabled=? AND (?=0 OR EXISTS(SELECT 1 FROM users u WHERE u.id=machines.owner_id AND u.blocked=0 AND u.access_revision=?)) AND NOT EXISTS(SELECT 1 FROM machine_deletions WHERE machine_id=machines.id) AND EXISTS(SELECT 1 FROM machine_connection_ops WHERE machine_id=machines.id AND lease_owner=? AND phase='working' AND lease_until>?)`, op.enabled, map[bool]string{true: "Подключено", false: "Отключено"}[op.enabled], op.connection.ID, op.connection.Revision, op.enabled, op.enabled, op.connection.OwnerRevision, op.owner, time.Now().Unix())
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
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE machine_connection_ops SET phase='cleanup' WHERE machine_id=? AND lease_owner=?", op.connection.ID, op.owner)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return failure(Unavailable, "Очистку подключения выполняет другой процесс")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE machines SET enabled=0,access_state='Ошибка настройки',access_error='Настройка подключения не подтверждена; очистка и повтор выполняются автоматически' WHERE id=? AND access_revision=?`, op.connection.ID, op.connection.Revision); err != nil {
		return err
	}
	return tx.Commit()
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
	rows, err := tx.QueryContext(ctx, `SELECT o.machine_id,COALESCE(m.public_key,''),COALESCE(m.tunnel_address,'') FROM machine_connection_ops o JOIN machines m ON m.id=o.machine_id WHERE o.lease_until<=? ORDER BY o.last_attempt,o.machine_id LIMIT 2`, now.Unix())
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
		if _, err = tx.ExecContext(ctx, "UPDATE machine_connection_ops SET phase='cleanup',lease_owner=?,lease_until=?,last_attempt=? WHERE machine_id=?", owner, now.Add(enrollmentLease).Unix(), now.Unix(), op.connection.ID); err != nil {
			return nil, err
		}
	}
	return operations, tx.Commit()
}
