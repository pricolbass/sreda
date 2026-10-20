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

type reconnectionCandidate struct {
	Connection                                Connection
	OwnerBlocked, Deleting, Pending           bool
	SourceRevision, OwnerRevision, LeaseUntil int64
}
type reconnectionDecision struct {
	Fresh          bool
	SourceRevision int64
}

func (m *Manager) PrepareReconnect(ctx context.Context, actor Actor, id, revision int64) (Reconnection, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	return m.store.prepareReconnect(ctx, id, token(), now, func(candidate reconnectionCandidate) (reconnectionDecision, error) {
		if candidate.Connection.OwnerID != actor.ID {
			return reconnectionDecision{}, failure(NotFound, "Машина не найдена")
		}
		if candidate.OwnerBlocked {
			return reconnectionDecision{}, failure(Unauthorized, "Доступ пользователя закрыт")
		}
		if candidate.Deleting {
			return reconnectionDecision{}, failure(Conflict, "Машина уже удаляется")
		}
		fresh := !candidate.Pending
		if candidate.Pending {
			if candidate.LeaseUntil > now.Unix() {
				return reconnectionDecision{}, failure(Unavailable, "Переподключение ещё выполняется")
			}
			if candidate.OwnerRevision != candidate.Connection.OwnerRevision || candidate.Connection.Revision != candidate.SourceRevision+1 {
				if revision != candidate.Connection.Revision {
					return reconnectionDecision{}, failure(Conflict, "Права или подключение изменились; обновите страницу")
				}
				fresh = true
			} else if revision != candidate.SourceRevision && revision != candidate.Connection.Revision {
				return reconnectionDecision{}, failure(Conflict, "Подключение изменилось; обновите страницу")
			}
		}
		source := candidate.SourceRevision
		if fresh {
			if revision != candidate.Connection.Revision {
				return reconnectionDecision{}, failure(Conflict, "Подключение изменилось; обновите страницу")
			}
			source = revision
		}
		return reconnectionDecision{Fresh: fresh, SourceRevision: source}, nil
	})
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
