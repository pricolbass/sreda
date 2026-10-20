package machine

import (
	"context"
	"errors"
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
	ops, opErr := m.store.ownerConnectionCleanup(ctx, ownerID, token(), time.Now().Unix(), time.Now().Add(enrollmentLease).Unix())
	failures = append(failures, opErr)
	for _, op := range ops {
		cleanupCtx, cancel := context.WithTimeout(ctx, enrollmentOperationTimeout)
		failures = append(failures, m.cleanupConnectionOperation(cleanupCtx, op))
		cancel()
	}
	problem := ""
	if err := errors.Join(failures...); err != nil {
		problem = err.Error()
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	failures = append(failures, m.store.finishOwnerClosure(persistCtx, ownerID, problem))
	return errors.Join(failures...)
}
