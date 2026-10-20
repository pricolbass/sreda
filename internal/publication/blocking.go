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
	routes := m.stopRoutesLocked(pubs)
	m.mu.Unlock()
	cancelRoutes(routes)
	var failures []error
	for _, p := range pubs {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
		closeErr := drainRoute(ctx, routes[p.ID], 10*time.Second)
		m.mu.Lock()
		state, message := "Отключена", ""
		if closeErr != nil {
			state, message = "Ошибка", "Не удалось подтвердить закрытие активных соединений"
			failures = append(failures, closeErr)
		}
		m.evictDrainedRouteLocked(p.ID, routes[p.ID], closeErr)
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
