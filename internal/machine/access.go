package machine

import (
	"context"
	"errors"
	"sreda/internal/tunnel"
	"time"
)

type connectionOperation struct {
	connection Connection
	owner      string
	enabled    bool
}

// connectionCandidate is a transaction snapshot; policy runs before any writes.
type connectionCandidate struct {
	Connection       Connection
	Deleting         bool
	OwnerBlocked     bool
	DesiredEnabled   bool
	Replacing        bool
	OperationPending bool
}
type connectionDecision struct {
	Change, AdvanceRevision bool
	State                   string
}

func (m *Manager) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gateway == nil {
		return failure(Unavailable, "сетевой шлюз не настроен")
	}
	return m.changeConnection(ctx, id, enabled, nil)
}

type accessCommand struct {
	actor    Actor
	revision int64
}

func (m *Manager) ChangeAccess(ctx context.Context, actor Actor, id, revision int64, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if revision < 1 {
		return failure(Invalid, "Обновите страницу: отсутствует версия подключения")
	}
	if m.gateway == nil {
		return failure(Unavailable, "Сетевой шлюз не настроен")
	}
	return m.changeConnection(ctx, id, enabled, nil, accessCommand{actor, revision})
}
func (m *Manager) changeConnection(ctx context.Context, id int64, enabled bool, recovery *connectionRecovery, command ...accessCommand) error {
	op, err := m.store.reserveConnectionOperation(ctx, id, enabled, token(), time.Now(), recovery != nil && enabled, func(candidate connectionCandidate) (connectionDecision, error) {
		if len(command) > 0 {
			c := command[0]
			if candidate.Connection.OwnerID != c.actor.ID {
				return connectionDecision{}, failure(NotFound, "Машина не найдена")
			}
			if c.revision != candidate.Connection.Revision {
				return connectionDecision{}, failure(Conflict, "Подключение уже изменилось. Обновите страницу")
			}
		}
		if recovery != nil {
			if candidate.Deleting || candidate.Replacing ||
				candidate.Connection.Revision != recovery.Revision ||
				candidate.Connection.OwnerRevision != recovery.OwnerRevision ||
				enabled != (candidate.DesiredEnabled && !candidate.OwnerBlocked) {
				return connectionDecision{}, nil
			}
		}
		if enabled && candidate.Replacing {
			return connectionDecision{}, failure(Unavailable, "Переподключение ожидает очистки")
		}
		if enabled && candidate.OwnerBlocked {
			return connectionDecision{}, failure(Unauthorized, "Доступ пользователя закрыт")
		}
		if candidate.Deleting {
			return connectionDecision{}, failure(Invalid, "Машина уже удаляется")
		}
		if candidate.Connection.PublicKey == "" {
			return connectionDecision{}, failure(Invalid, "Машина ещё не подключена")
		}
		if candidate.OperationPending {
			return connectionDecision{}, failure(Unavailable, "Предыдущее изменение подключения ещё ожидает очистки")
		}
		state := "Отключается"
		if enabled {
			state = "Настраивается"
		}
		return connectionDecision{Change: true, AdvanceRevision: len(command) > 0, State: state}, nil
	})
	if err != nil {
		return err
	}
	if op.connection.ID == 0 {
		return nil
	}
	operationCtx, cancel := context.WithTimeout(ctx, enrollmentOperationTimeout)
	peer := tunnel.Peer{MachineID: op.connection.ID, PublicKey: op.connection.PublicKey, Address: op.connection.Address}
	if enabled {
		err = m.gateway.ApplyPeer(operationCtx, peer)
	} else {
		err = m.gateway.RemovePeer(operationCtx, peer)
	}
	cancel()
	if err == nil {
		err = m.store.finishConnectionOperation(ctx, op)
	}
	if err != nil {
		cleanupCtx, stop := context.WithTimeout(context.Background(), enrollmentOperationTimeout)
		defer stop()
		_ = m.cleanupConnectionOperation(cleanupCtx, op)
		return failure(Unavailable, "Изменение подключения не подтверждено; доступ остаётся выключенным")
	}
	m.contacts.Delete(id)
	return nil
}
func (m *Manager) cleanupConnectionOperation(ctx context.Context, op connectionOperation) error {
	if m.gateway == nil {
		return failure(Unavailable, "сетевой шлюз не настроен")
	}
	if err := m.store.markConnectionCleanup(ctx, op); err != nil {
		return err
	}
	operationCtx, cancel := context.WithTimeout(ctx, enrollmentOperationTimeout)
	err := m.gateway.RemovePeer(operationCtx, tunnel.Peer{MachineID: op.connection.ID, PublicKey: op.connection.PublicKey, Address: op.connection.Address})
	cancel()
	if err == nil {
		err = m.store.finishConnectionCleanup(ctx, op)
	}
	if err != nil {
		releaseCtx, stop := context.WithTimeout(context.Background(), 3*time.Second)
		defer stop()
		_ = m.store.releaseConnectionCleanup(releaseCtx, op)
	}
	return err
}
func (m *Manager) reconcileConnectionOperations(ctx context.Context) error {
	operations, err := m.store.claimConnectionCleanup(ctx, token(), time.Now())
	if err != nil {
		return err
	}
	var failures []error
	for _, op := range operations {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
		if err = m.cleanupConnectionOperation(ctx, op); err != nil {
			failures = append(failures, err)
		}
	}
	return errors.Join(failures...)
}

// connectionRecovery fences restoration against the snapshot's connection and
// owner epochs. Restoration may apply current intent, never replace newer intent.
type connectionRecovery struct {
	Revision, OwnerRevision int64
}
