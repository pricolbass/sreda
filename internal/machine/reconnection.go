package machine

import (
	"context"
	"errors"
	"sreda/internal/tunnel"
	"time"
)

// Reconnection is an opaque reservation: callers can coordinate gateway closure
// but cannot change the lease or credentials used by the machine module.
type Reconnection struct {
	connection Connection
	owner      string
}

func (r Reconnection) MachineID() int64     { return r.connection.ID }
func (r Reconnection) Revision() int64      { return r.connection.Revision }
func (r Reconnection) OwnerRevision() int64 { return r.connection.OwnerRevision }

func (m *Manager) PrepareReconnect(ctx context.Context, actor Actor, id, revision int64) (Reconnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.prepareReconnect(ctx, actor, id, revision, token(), time.Now())
}
func (m *Manager) ReconnectFailed(ctx context.Context, r Reconnection, message string) error {
	return m.store.releaseReconnect(ctx, r, message)
}
func (m *Manager) CompleteReconnect(ctx context.Context, r Reconnection) (Enrollment, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gateway == nil {
		return Enrollment{}, failure(Unavailable, "Сетевой шлюз недоступен; прежнее подключение ещё не отозвано")
	}

	enrollment, operation, err := m.store.claimReconnectPending(ctx, r, time.Now())
	if err != nil {
		return Enrollment{}, err
	}
	var failures []error
	if enrollment != nil {
		failures = append(failures, m.cleanupEnrollment(ctx, *enrollment, enrollmentCleanupTimeout))
	}
	if operation != nil {
		failures = append(failures, m.cleanupConnectionOperation(ctx, *operation))
	}
	if errors.Join(failures...) != nil {
		return Enrollment{}, failure(Unavailable, "Очистка прежней настройки не подтверждена; повторите переподключение")
	}
	if err := m.store.reconnectReady(ctx, r); err != nil {
		return Enrollment{}, err
	}
	if r.connection.PublicKey != "" {
		removeCtx, cancel := context.WithTimeout(ctx, enrollmentOperationTimeout)
		err := m.gateway.RemovePeer(removeCtx, tunnel.Peer{MachineID: r.connection.ID, PublicKey: r.connection.PublicKey, Address: r.connection.Address})
		cancel()
		if err != nil {
			return Enrollment{}, failure(Unavailable, "Отзыв прежнего подключения не подтверждён; повторите переподключение")
		}
	}
	e := Enrollment{ID: r.connection.ID, Mode: r.connection.Mode, Code: token(), ExpiresAt: time.Now().Add(CodeLifetime)}
	if err := m.store.finishReconnect(ctx, r, e); err != nil {
		return Enrollment{}, err
	}
	m.contacts.Delete(r.connection.ID)
	return e, nil
}
