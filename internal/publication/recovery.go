package publication

import (
	"context"
	"errors"
	"sreda/internal/agentprotocol"
	"sreda/internal/machine"
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
		route := m.stopRouteLocked(p.ID)
		m.mu.Unlock()
		closeErr := drainRoute(ctx, route, 10*time.Second)
		m.mu.Lock()
		m.evictDrainedRouteLocked(p.ID, route, closeErr)
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

// ReconcileManual confirms only committed, active manual connections. The caller
// runs peer recovery first; failed or unfinished peer work remains ineligible.
func (m *Module) ReconcileManual(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	candidates, err := m.store.pendingManualConfirmations(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, candidate := range candidates {
		if candidate.Mode != machine.ManualMode || !candidate.Enabled || !candidate.DesiredEnabled || candidate.OwnerBlocked || candidate.PendingOperation {
			continue
		}
		failures = append(failures, m.store.confirmManual(ctx, candidate.Identity))
	}
	return errors.Join(failures...)
}

type manualConfirmationCandidate struct {
	Identity         agentprotocol.ConnectionIdentity
	Mode             machine.Mode
	Enabled          bool
	DesiredEnabled   bool
	OwnerBlocked     bool
	PendingOperation bool
}
