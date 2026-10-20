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
	return m.store.block(ctx, actorID, userID, func(candidate accountAccessCandidate) (AccountAccess, error) {
		a, err := authorizeAccountAccess(candidate, revision)
		if err != nil {
			return a, err
		}
		if !a.Blocked {
			a.Revision++
		}
		a.Blocked, a.State, a.Error = true, "Отключение выполняется", ""
		return a, nil
	})
}
func (m *Manager) Unblock(ctx context.Context, actorID, userID, revision int64) error {
	return m.store.unblock(ctx, actorID, userID, func(candidate accountAccessCandidate) (accountAccessDecision, error) {
		a, err := authorizeAccountAccess(candidate, revision)
		if err != nil || !a.Blocked {
			return accountAccessDecision{}, err
		}
		if a.State != "Доступ закрыт" {
			return accountAccessDecision{}, AccessIncomplete
		}
		a.Blocked, a.State, a.Error = false, "Вход разрешён", ""
		a.Revision++
		return accountAccessDecision{Account: a, Change: true}, nil
	})
}
func (m *Manager) FinishBlock(ctx context.Context, userID, revision int64, lease, problem string) error {
	state := "Доступ закрыт"
	if problem != "" {
		state = "Ошибка закрытия доступа"
	}
	return m.store.finishBlock(ctx, userID, revision, lease, state, problem)
}
func (m *Manager) PendingClosures(ctx context.Context) ([]AccountAccess, error) {
	return m.store.pendingClosures(ctx)
}
func (m *Manager) ClaimClosure(ctx context.Context, id, revision int64) (string, error) {
	return m.store.claimClosure(ctx, id, revision, token())
}

// accountAccessCandidate contains one transaction's actor and account snapshot.
type accountAccessCandidate struct {
	ActorRole string
	Account   AccountAccess
}

func authorizeAccountAccess(candidate accountAccessCandidate, revision int64) (AccountAccess, error) {
	a := candidate.Account
	if candidate.ActorRole != "admin" {
		return AccountAccess{}, Forbidden
	}
	if a.ID == 0 {
		return a, UserNotFound
	}
	if a.Revision != revision {
		return a, AccessConflict
	}
	return a, nil
}

type accountAccessDecision struct {
	Account AccountAccess
	Change  bool
}
