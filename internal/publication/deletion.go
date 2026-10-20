package publication

import (
	"context"
	"time"
)

type Deletion struct {
	ID          string
	Revision    int64
	ConfirmName string
}
type DeletionResult struct {
	Completed bool `json:"completed"`
}

// Delete commits irrevocable deletion intent before draining. The name remains
// reserved until the gateway closes and, for agent mode, the agent confirms removal.
func (m *Module) Delete(ctx context.Context, actor Actor, request Deletion) (DeletionResult, error) {
	if request.Revision < 1 {
		return DeletionResult{}, fail(Invalid, "Обновите страницу: отсутствует версия публикации")
	}
	m.mu.Lock()
	p, completed, err := m.store.beginDeletion(ctx, request.ID, func(p Publication, deleted bool) (bool, error) {
		if p.ID == "" || p.OwnerID != actor.ID {
			return false, fail(NotFound, "Публикация не найдена")
		}
		if request.ConfirmName != p.Subdomain {
			return false, fail(Invalid, "Подтвердите потерю имени: введите поддомен публикации")
		}
		if deleted || p.DeletionPending {
			return false, nil
		}
		if p.Revision != request.Revision {
			return false, fail(Conflict, "Публикация уже изменилась. Обновите страницу")
		}
		return true, nil
	})
	if err != nil || completed {
		m.mu.Unlock()
		return DeletionResult{Completed: completed}, err
	}
	route := m.forwarder.routes[p.ID]
	if route != nil {
		route.stopAdmission()
	}
	m.mu.Unlock()
	closeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if route != nil {
		err = route.closeAndWait(closeCtx)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil && m.forwarder.routes[p.ID] == route {
		delete(m.forwarder.routes, p.ID)
	}
	persistCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer stop()
	if err != nil {
		_, _ = m.store.recordDeletionClosure(persistCtx, p.ID, false, "Не удалось подтвердить закрытие соединений; повторите удаление")
		return DeletionResult{}, fail(Unavailable, "Не удалось подтвердить закрытие соединений; имя остаётся зарезервированным")
	}
	completed, err = m.store.recordDeletionClosure(persistCtx, p.ID, true, "Ожидается подтверждение удаления маршрута агентом")
	return DeletionResult{Completed: completed}, err
}
