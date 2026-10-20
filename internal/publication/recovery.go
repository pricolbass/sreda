package publication

import (
	"context"
	"errors"
	"time"
)

// Reconcile resumes committed closure intent. It never creates a new intention
// or replays a human confirmation; deleted IDs remain irrecoverable.
func (m *Module) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	pending, err := m.store.pendingClosures(ctx)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	var failures []error
	for _, p := range pending {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
		m.mu.Lock()
		current, err := m.store.claimClosure(ctx, p.ID, p.Revision)
		if err != nil || !current {
			m.mu.Unlock()
			failures = append(failures, err)
			continue
		}
		route := m.forwarder.routes[p.ID]
		if route != nil {
			route.stopAdmission()
		}
		m.mu.Unlock()
		closeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		var closeErr error
		if route != nil {
			closeErr = route.closeAndWait(closeCtx)
		}
		cancel()
		m.mu.Lock()
		if closeErr == nil && m.forwarder.routes[p.ID] == route {
			delete(m.forwarder.routes, p.ID)
		}
		persistCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
		state, message := "Отключена", ""
		if closeErr != nil {
			state, message = "Ошибка", "Не удалось подтвердить закрытие активных соединений"
		}
		if p.DeletionPending {
			_, err = m.store.recordDeletionClosure(persistCtx, p.ID, closeErr == nil, message)
		} else {
			err = m.store.finishAccess(persistCtx, p.ID, p.Revision, state, message)
		}
		stop()
		m.mu.Unlock()
		failures = append(failures, closeErr, err)
	}
	return errors.Join(failures...)
}
