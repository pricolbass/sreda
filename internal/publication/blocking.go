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
	// Initiate every closure before waiting: one blocked downstream must not
	// prevent cancellation of the other publications when the phase budget ends.
	for _, route := range routes {
		route.cancelActive()
	}
	var failures []error
	for _, p := range pubs {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
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
		if p.DeletionPending {
			_, err := m.store.recordDeletionClosure(persistCtx, p.ID, closeErr == nil, message)
			failures = append(failures, err)
		} else {
			failures = append(failures, m.store.finishAccess(persistCtx, p.ID, p.Revision, state, message))
		}
		stop()
		m.mu.Unlock()
	}
	return errors.Join(failures...)
}
