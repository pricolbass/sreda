package identity

import "context"

const AccessConflict Failure = "Состояние доступа изменилось; обновите страницу"
const AccessIncomplete Failure = "Сначала завершите закрытие доступа"

type AccountAccess struct {
	ID           int64
	Login        string
	Blocked      bool
	Revision     int64
	State, Error string
}

func (m *Manager) AccountAccess(ctx context.Context, actorID int64) ([]AccountAccess, error) {
	if err := m.administratorID(ctx, actorID); err != nil {
		return nil, err
	}
	return m.store.accountAccess(ctx)
}
func (m *Manager) Block(ctx context.Context, actorID, userID, revision int64) (AccountAccess, error) {
	return m.store.block(ctx, actorID, userID, revision)
}
func (m *Manager) Unblock(ctx context.Context, actorID, userID, revision int64) error {
	return m.store.unblock(ctx, actorID, userID, revision)
}
func (m *Manager) FinishBlock(ctx context.Context, userID, revision int64, problem string) error {
	return m.store.finishBlock(ctx, userID, revision, problem)
}
