package machine

import (
	"context"
	"database/sql"
	"errors"
)

func (s *sqliteStore) recoverAgent(ctx context.Context, credential []byte, publicKey string) (Connection, error) {
	var c Connection
	err := s.db.QueryRowContext(ctx, `SELECT m.id,m.owner_id,m.public_key,m.tunnel_address,m.proxy_token,m.enabled,m.access_revision,u.access_revision FROM machines m JOIN users u ON u.id=m.owner_id WHERE m.credential_hash=? AND m.public_key=? AND m.mode='agent' AND m.enabled=0 AND m.desired_enabled=0 AND u.blocked=0 AND NOT EXISTS(SELECT 1 FROM machine_deletions d WHERE d.machine_id=m.id) AND NOT EXISTS(SELECT 1 FROM machine_reconnections x WHERE x.machine_id=m.id)`, credential, publicKey).Scan(&c.ID, &c.OwnerID, &c.PublicKey, &c.Address, &c.ProxyToken, &c.Enabled, &c.Revision, &c.OwnerRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return c, failure(Unauthorized, "Подключение отключено или отозвано")
	}
	return c, err
}
