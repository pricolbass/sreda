package publication

import (
	"context"
	"errors"
	"time"
)

// DisableOwner closes every publication before confirming a user block.
func (m *Module) DisableOwner(ctx context.Context, ownerID int64) error {
	m.mu.Lock()
	pubs, err := m.store.disableOwner(ctx, ownerID)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	routes := make(map[string]*publicationRoute)
	for _, p := range pubs {
		if r := m.forwarder.routes[p.ID]; r != nil {
			r.stopAdmission()
			routes[p.ID] = r
		}
	}
	m.mu.Unlock()
	var failures []error
	for _, p := range pubs {
		closeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var closeErr error
		if r := routes[p.ID]; r != nil {
			closeErr = r.closeAndWait(closeCtx)
		}
		cancel()
		m.mu.Lock()
		state, message := "Отключена", ""
		if closeErr != nil {
			state, message = "Ошибка", "Не удалось подтвердить закрытие активных соединений"
			failures = append(failures, closeErr)
		} else if m.forwarder.routes[p.ID] == routes[p.ID] {
			delete(m.forwarder.routes, p.ID)
		}
		persistCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		failures = append(failures, m.store.finishAccess(persistCtx, p.ID, p.Revision, state, message))
		stop()
		m.mu.Unlock()
	}
	return errors.Join(failures...)
}
func (s *sqliteStore) disableOwner(ctx context.Context, ownerID int64) ([]Publication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE machine_control SET generation=generation+1 WHERE machine_id IN(SELECT id FROM machines WHERE owner_id=?)`, ownerID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE publications SET desired_enabled=0,state='Отключается',error='',revision=revision+1,generation=(SELECT generation FROM machine_control WHERE machine_id=publications.machine_id) WHERE machine_id IN(SELECT id FROM machines WHERE owner_id=?)`, ownerID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,revision FROM publications WHERE machine_id IN(SELECT id FROM machines WHERE owner_id=?)`, ownerID)
	if err != nil {
		return nil, err
	}
	var out []Publication
	for rows.Next() {
		var p Publication
		if err := rows.Scan(&p.ID, &p.Revision); err != nil {
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
