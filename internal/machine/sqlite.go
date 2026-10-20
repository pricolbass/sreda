package machine

import (
	"context"
	"database/sql"
	"errors"
	"sreda/internal/agentprotocol"
	"time"
)

type sqliteStore struct{ db *sql.DB }

// New composes the local SQLite adapter. Schema installation belongs to application startup.
func New(db *sql.DB, now func() time.Time) *Manager {
	if now == nil {
		now = time.Now
	}
	return &Manager{store: &sqliteStore{db: db}, now: now}
}
func (s *sqliteStore) list(ctx context.Context, actor Actor) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.id,m.owner_id,m.name,u.login,m.enabled,m.last_seen,m.mode,EXISTS(SELECT 1 FROM machine_deletions d WHERE d.machine_id=m.id),COALESCE((SELECT error FROM machine_deletions d WHERE d.machine_id=m.id),''),m.access_revision,m.desired_enabled,m.access_state,m.access_error,m.public_key IS NOT NULL FROM machines m JOIN users u ON u.id=m.owner_id WHERE m.owner_id=? OR ? ORDER BY m.id`, actor.ID, actor.Admin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []Record{}
	for rows.Next() {
		var r Record
		var last sql.NullInt64
		if err = rows.Scan(&r.ID, &r.OwnerID, &r.Name, &r.Owner, &r.Enabled, &last, &r.Mode, &r.DeletionPending, &r.DeleteError, &r.Revision, &r.DesiredEnabled, &r.AccessState, &r.AccessError, &r.Enrolled); err != nil {
			return nil, err
		}
		if last.Valid {
			r.LastSeen = time.Unix(last.Int64, 0)
		}
		records = append(records, r)
	}
	return records, rows.Err()
}
func (s *sqliteStore) find(ctx context.Context, actor Actor, id int64) (Record, error) {
	var r Record
	err := s.db.QueryRowContext(ctx, `SELECT id,name FROM machines WHERE id=? AND(owner_id=? OR ?)`, id, actor.ID, actor.Admin).Scan(&r.ID, &r.Name)
	if errors.Is(err, sql.ErrNoRows) {
		return r, failure(NotFound, "Машина не найдена")
	}
	return r, err
}
func (s *sqliteStore) connection(ctx context.Context, id int64) (Connection, error) {
	var c Connection
	var last sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT id,owner_id,COALESCE(public_key,''),COALESCE(tunnel_address,''),COALESCE(proxy_token,''),enabled,last_seen,mode,access_revision,(SELECT access_revision FROM users WHERE id=machines.owner_id) FROM machines WHERE id=?`, id).Scan(&c.ID, &c.OwnerID, &c.PublicKey, &c.Address, &c.ProxyToken, &c.Enabled, &last, &c.Mode, &c.Revision, &c.OwnerRevision)
	if last.Valid {
		c.LastSeen = time.Unix(last.Int64, 0)
	}
	return c, err
}
func (s *sqliteStore) agent(ctx context.Context, credential []byte) (Connection, error) {
	var c Connection
	err := s.db.QueryRowContext(ctx, `SELECT id,owner_id,public_key,tunnel_address,proxy_token,enabled,access_revision,(SELECT access_revision FROM users WHERE id=machines.owner_id) FROM machines WHERE credential_hash=? AND enabled=1 AND mode='agent' AND EXISTS(SELECT 1 FROM users u WHERE u.id=machines.owner_id AND u.blocked=0)`, credential).Scan(&c.ID, &c.OwnerID, &c.PublicKey, &c.Address, &c.ProxyToken, &c.Enabled, &c.Revision, &c.OwnerRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return c, failure(Unauthorized, "Подключение отключено или отозвано")
	}
	return c, err
}
func (s *sqliteStore) observe(ctx context.Context, identity agentprotocol.ConnectionIdentity, now int64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE machines SET last_seen=? WHERE id=? AND enabled=1 AND access_revision=? AND mode='agent' AND EXISTS(SELECT 1 FROM users u WHERE u.id=machines.owner_id AND u.blocked=0 AND u.access_revision=?)`, now, identity.MachineID, identity.Revision, identity.OwnerRevision)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err == nil && n != 1 {
		return failure(Unauthorized, "Подключение отключено или отозвано")
	}
	return err
}
