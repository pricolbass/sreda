package machine

import (
	"context"
	"fmt"
	"sreda/internal/tunnel"
	"strings"
	"time"
)

type BlockingPublication struct{ ID, Subdomain string }
type BlockedDeletion struct{ Publications []BlockingPublication }

func (e *BlockedDeletion) Error() string {
	names := make([]string, 0, len(e.Publications))
	for _, p := range e.Publications {
		names = append(names, p.Subdomain)
	}
	return "Сначала удалите связанные публикации, включая отключённые: " + strings.Join(names, ", ")
}

type DeletionResult struct {
	Completed bool `json:"completed"`
}

func (m *Manager) Delete(ctx context.Context, actor Actor, id int64) (DeletionResult, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	intent, done, err := m.store.reserveDeletion(ctx, id, token(), time.Now(), func(candidate deletionCandidate) error {
		if candidate.OwnerID != actor.ID {
			return failure(NotFound, "Машина не найдена")
		}
		if len(candidate.Publications) > 0 {
			return &BlockedDeletion{Publications: candidate.Publications}
		}
		return nil
	})
	if err != nil || done {
		return DeletionResult{Completed: done}, err
	}
	return m.cleanupDeletion(ctx, intent)
}
func (m *Manager) cleanupDeletion(ctx context.Context, intent deletionIntent) (DeletionResult, error) {
	if intent.waiting {
		return DeletionResult{}, nil
	}
	if intent.enrollment != nil {
		if m.gateway == nil {
			return m.deletionFailure(intent, "Сетевой шлюз недоступен; очистка не подтверждена")
		}
		if err := m.cleanupEnrollment(ctx, *intent.enrollment, enrollmentCleanupTimeout); err != nil {
			return m.deletionFailure(intent, "Очистка незавершённого подключения не подтверждена")
		}
	}
	if intent.operation != nil {
		if err := m.cleanupConnectionOperation(ctx, *intent.operation); err != nil {
			return m.deletionFailure(intent, "Очистка изменения подключения не подтверждена")
		}
	}
	if intent.connection.PublicKey != "" {
		if m.gateway == nil {
			return m.deletionFailure(intent, "Сетевой шлюз недоступен; отключение не подтверждено")
		}
		operationCtx, cancel := context.WithTimeout(ctx, enrollmentOperationTimeout)
		err := m.gateway.RemovePeer(operationCtx, tunnel.Peer{MachineID: intent.connection.ID, PublicKey: intent.connection.PublicKey, Address: intent.connection.Address})
		cancel()
		if err != nil {
			return m.deletionFailure(intent, "Отзыв подключения не подтверждён; повторите удаление")
		}
	}
	persistCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	if err := m.store.finishDeletion(persistCtx, intent); err != nil {
		return m.deletionFailure(intent, "Завершение удаления не подтверждено; повторите позже")
	}
	return DeletionResult{Completed: true}, nil
}
func (m *Manager) deletionFailure(intent deletionIntent, message string) (DeletionResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = m.store.releaseDeletion(ctx, intent, message)
	return DeletionResult{}, failure(Unavailable, message)
}
func (m *Manager) reconcileDeletions(ctx context.Context) error {
	candidates, err := m.store.pendingDeletions(ctx)
	if err != nil {
		return err
	}
	var failures []string
	for _, candidate := range candidates {
		intent, done, err := m.store.reserveDeletion(ctx, candidate.ID, token(), time.Now(), func(deletionCandidate) error { return nil })
		if err == nil && !done {
			_, err = m.cleanupDeletion(ctx, intent)
		}
		if err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("очистка удаляемых машин: %s", strings.Join(failures, "; "))
	}
	return nil
}
