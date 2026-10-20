package machine

import (
	"context"
	"errors"
	"sreda/internal/tunnel"
	"time"
)

func (m *Manager) DisableOwner(ctx context.Context, ownerID int64) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	peers, err := m.store.disableOwner(ctx, ownerID)
	if err != nil {
		return err
	}
	var failures []error
	for _, peer := range peers {
		if m.gateway == nil {
			failures = append(failures, failure(Unavailable, "Сетевой шлюз недоступен"))
			continue
		}
		opCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		err := m.gateway.RemovePeer(opCtx, peer)
		cancel()
		if err != nil {
			failures = append(failures, failure(Unavailable, "Отключение peer не подтверждено"))
		}
		m.contacts.Delete(peer.MachineID)
	}
	intents, pendingErr := m.store.ownerEnrollmentCleanup(ctx, ownerID, token(), time.Now().Unix(), time.Now().Add(enrollmentLease).Unix())
	failures = append(failures, pendingErr)
	for _, intent := range intents {
		cleanupCtx, cancel := context.WithTimeout(ctx, enrollmentOperationTimeout)
		failures = append(failures, m.cleanupEnrollment(cleanupCtx, intent, enrollmentOperationTimeout))
		cancel()
	}
	return errors.Join(failures...)
}
func (s *sqliteStore) disableOwner(ctx context.Context, ownerID int64) ([]tunnel.Peer, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE machines SET enabled=0,last_seen=NULL,code_hash=NULL,code_expires_at=NULL WHERE owner_id=?`, ownerID); err != nil {
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
