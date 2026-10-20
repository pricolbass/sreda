package publication

import (
	"context"
	"time"
)

type AccessChange struct {
	ID       string
	Revision int64
	Enabled  bool
}

// SetEnabled persists intent before closing access. Only a drained gateway route
// can be reported disabled; the remote agent is not part of that confirmation.
func (m *Module) SetEnabled(ctx context.Context, actor Actor, change AccessChange) error {
	if change.Revision < 1 {
		return fail(Invalid, "Обновите страницу: отсутствует версия публикации")
	}
	m.mu.Lock()
	p, err := m.store.changeAccess(ctx, change.ID, func(candidate accessCandidate) (accessDecision, error) {
		p := candidate.Publication
		if p.ID == "" || (p.OwnerID != actor.ID && (!actor.Admin || change.Enabled)) {
			return accessDecision{}, fail(NotFound, "Публикация не найдена")
		}
		if change.Enabled && candidate.OwnerBlocked {
			return accessDecision{}, fail(Conflict, "Доступ пользователя закрыт")
		}
		if p.DeletionPending {
			return accessDecision{}, fail(Conflict, "Публикация уже удаляется")
		}
		if p.DesiredEnabled == change.Enabled {
			return accessDecision{}, nil
		}
		if p.Revision != change.Revision {
			return accessDecision{}, fail(Conflict, "Публикация уже изменилась. Обновите страницу")
		}
		if change.Enabled && (!candidate.MachineEnabled || p.State != "Отключена") {
			return accessDecision{}, fail(Conflict, "Сначала завершите отключение и включите подключение машины")
		}
		state := "Отключается"
		if change.Enabled {
			state = "Настраивается"
			endpoint, err := m.transport.Endpoint(candidate.Delivery)
			if err != nil {
				return accessDecision{}, fail(Unavailable, "Настройки доставки публикации не подтверждены")
			}
			if !endpoint.AgentControlled {
				state = "Настроена"
			}
		}
		return accessDecision{Change: true, Enabled: change.Enabled, State: state}, nil
	})
	if err != nil {
		m.mu.Unlock()
		return err
	}
	if change.Enabled {
		m.mu.Unlock()
		return nil
	}
	route := m.stopRouteLocked(p.ID)
	m.mu.Unlock()
	closeErr := drainRoute(ctx, route, 10*time.Second)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.evictDrainedRouteLocked(p.ID, route, closeErr)
	persistCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer stop()
	if closeErr != nil {
		_ = m.store.finishAccess(persistCtx, p.ID, p.Revision, "Ошибка", "Не удалось подтвердить закрытие активных соединений; повторите отключение")
		return fail(Unavailable, "Не удалось подтвердить закрытие активных соединений; повторите отключение")
	}
	return m.store.finishAccess(persistCtx, p.ID, p.Revision, "Отключена", "")
}
