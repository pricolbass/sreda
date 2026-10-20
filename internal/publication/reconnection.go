package publication

import (
	"context"
	"errors"
	"sreda/internal/agentprotocol"
	"time"
)

// SuspendMachine invalidates cached proxy endpoints while retaining publication
// intent. A new connection receives fresh proxy credentials for the same IDs.
func (m *Module) SuspendMachine(ctx context.Context, id, revision, ownerRevision int64) error {
	m.mu.Lock()
	pubs, err := m.store.suspendMachine(ctx, id, revision, ownerRevision)
	if err != nil {
		m.mu.Unlock()
		return err
	}
	routes := m.stopRoutesLocked(pubs)
	m.mu.Unlock()
	cancelRoutes(routes)
	var failures []error
	for _, p := range pubs {
		closeErr := drainRoute(ctx, routes[p.ID], 10*time.Second)
		m.mu.Lock()
		m.evictDrainedRouteLocked(p.ID, routes[p.ID], closeErr)
		if closeErr != nil {
			failures = append(failures, fail(Unavailable, "Закрытие прежних соединений публикации не подтверждено"))
		}
		m.mu.Unlock()
	}
	return errors.Join(failures...)
}

// ConfirmManual restores configured publication status after the shared machine
// module has confirmed the new manual peer; no agent acknowledgment exists.
func (m *Module) ConfirmManual(ctx context.Context, identity agentprotocol.ConnectionIdentity) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.confirmManual(ctx, identity)
}
