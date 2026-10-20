package machine

import (
	"context"
	"sreda/internal/tunnel"
)

func (s *sqliteStore) disableOwner(ctx context.Context, ownerID int64) ([]tunnel.Peer, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE machines SET enabled=0,desired_enabled=0,access_revision=access_revision+1,access_state='Отключается',access_error='',last_seen=NULL,code_hash=NULL,code_expires_at=NULL WHERE owner_id=?`, ownerID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,public_key,tunnel_address FROM machines WHERE owner_id=? AND public_key IS NOT NULL`, ownerID)
	if err != nil {
		return nil, err
	}
	var out []tunnel.Peer
	for rows.Next() {
		var p tunnel.Peer
		if err := rows.Scan(&p.MachineID, &p.PublicKey, &p.Address); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}

func (s *sqliteStore) ownerEnrollmentCleanup(ctx context.Context, ownerID int64, leaseOwner string, now, until int64) ([]enrollmentIntent, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT e.machine_id,e.public_key,e.tunnel_address,e.lease_until FROM machine_enrollments e JOIN machines m ON m.id=e.machine_id WHERE m.owner_id=?`, ownerID)
	if err != nil {
		return nil, err
	}
	var intents []enrollmentIntent
	live := false
	for rows.Next() {
		var i enrollmentIntent
		var lease int64
		if err := rows.Scan(&i.connection.ID, &i.connection.PublicKey, &i.connection.Address, &lease); err != nil {
			rows.Close()
			return nil, err
		}
		if lease > now {
			live = true
			continue
		}
		i.owner = leaseOwner
		i.phase = "cleanup"
		intents = append(intents, i)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, i := range intents {
		if _, err := tx.ExecContext(ctx, `UPDATE machine_enrollments SET phase='cleanup',lease_owner=?,lease_until=?,last_attempt=? WHERE machine_id=?`, leaseOwner, until, now, i.connection.ID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if live {
		return intents, failure(Unavailable, "Предыдущая настройка подключения ещё выполняется; повторите закрытие доступа")
	}
	return intents, nil
}

func (s *sqliteStore) ownerConnectionCleanup(ctx context.Context, ownerID int64, leaseOwner string, now, until int64) ([]connectionOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT o.machine_id,COALESCE(m.public_key,''),COALESCE(m.tunnel_address,''),o.lease_until FROM machine_connection_ops o JOIN machines m ON m.id=o.machine_id WHERE m.owner_id=?`, ownerID)
	if err != nil {
		return nil, err
	}
	var ops []connectionOperation
	live := false
	for rows.Next() {
		var op connectionOperation
		var lease int64
		op.owner = leaseOwner
		if err := rows.Scan(&op.connection.ID, &op.connection.PublicKey, &op.connection.Address, &lease); err != nil {
			rows.Close()
			return nil, err
		}
		if lease > now {
			live = true
			continue
		}
		ops = append(ops, op)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, op := range ops {
		if _, err := tx.ExecContext(ctx, `UPDATE machine_connection_ops SET desired_enabled=0,phase='cleanup',lease_owner=?,lease_until=?,last_attempt=? WHERE machine_id=?`, leaseOwner, until, now, op.connection.ID); err != nil {
			return nil, err
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	if live {
		return ops, failure(Unavailable, "Применение подключения ещё выполняется; повторите закрытие доступа")
	}
	return ops, nil
}
func (s *sqliteStore) finishOwnerClosure(ctx context.Context, ownerID int64, problem string) error {
	state := "Отключено"
	if problem != "" {
		state = "Ошибка отключения"
	}
	_, err := s.db.ExecContext(ctx, `UPDATE machines SET access_state=?,access_error=? WHERE owner_id=? AND desired_enabled=0`, state, problem, ownerID)
	return err
}
