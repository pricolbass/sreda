package machine

import "context"

// RecoverAgent allows a credential already committed while intentionally off to
// finish local enrollment after a lost response. It never authorizes heartbeat,
// route delivery, or a network change, and requires the matching local public key.
func (m *Manager) RecoverAgent(ctx context.Context, credential, publicKey string) (Connection, error) {
	if len(credential) != 43 || !validKey(publicKey) || m.gateway == nil {
		return Connection{}, failure(Unauthorized, "Подключение недоступно")
	}
	return m.store.recoverAgent(ctx, hash(credential), publicKey)
}
