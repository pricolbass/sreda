package machine

import (
	"context"
	"database/sql"
	"errors"
	"sreda/internal/tunnel"
	"time"
)

type sqliteStore struct{ db *sql.DB }

// New composes the local SQLite adapter. Schema installation belongs to application startup.
func New(db *sql.DB) *Manager { return &Manager{store: &sqliteStore{db: db}} }
func (s *sqliteStore) create(ctx context.Context, ownerID int64, name string, code []byte, expiry, created int64) (int64, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO machines(owner_id,name,code_hash,code_expires_at,created_at) VALUES(?,?,?,?,?)`, ownerID, name, code, expiry, created)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}
func (s *sqliteStore) list(ctx context.Context, actor Actor) ([]Record, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.id,m.owner_id,m.name,u.login,m.enabled,m.last_seen FROM machines m JOIN users u ON u.id=m.owner_id WHERE m.owner_id=? OR ? ORDER BY m.id`, actor.ID, actor.Admin)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	records := []Record{}
	for rows.Next() {
		var r Record
		var last sql.NullInt64
		if err = rows.Scan(&r.ID, &r.OwnerID, &r.Name, &r.Owner, &r.Enabled, &last); err != nil {
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
	err := s.db.QueryRowContext(ctx, `SELECT id,owner_id,COALESCE(public_key,''),COALESCE(tunnel_address,''),COALESCE(proxy_token,''),enabled,last_seen FROM machines WHERE id=?`, id).Scan(&c.ID, &c.OwnerID, &c.PublicKey, &c.Address, &c.ProxyToken, &c.Enabled, &last)
	if last.Valid {
		c.LastSeen = time.Unix(last.Int64, 0)
	}
	return c, err
}
func (s *sqliteStore) agent(ctx context.Context, credential []byte) (Connection, error) {
	var c Connection
	err := s.db.QueryRowContext(ctx, `SELECT id,owner_id,public_key,tunnel_address,proxy_token,enabled FROM machines WHERE credential_hash=? AND enabled=1`, credential).Scan(&c.ID, &c.OwnerID, &c.PublicKey, &c.Address, &c.ProxyToken, &c.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return c, failure(Unauthorized, "Подключение отключено или отозвано")
	}
	return c, err
}
func (s *sqliteStore) observe(ctx context.Context, id, now int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE machines SET last_seen=? WHERE id=? AND enabled=1`, now, id)
	return err
}
func (s *sqliteStore) setEnabled(ctx context.Context, id int64, enabled bool) error {
	_, err := s.db.ExecContext(ctx, `UPDATE machines SET enabled=? WHERE id=?`, enabled, id)
	return err
}
func (s *sqliteStore) enabledPeers(ctx context.Context) ([]tunnel.Peer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,public_key,tunnel_address FROM machines WHERE enabled=1 AND public_key IS NOT NULL`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	peers := []tunnel.Peer{}
	for rows.Next() {
		var p tunnel.Peer
		if err = rows.Scan(&p.MachineID, &p.PublicKey, &p.Address); err != nil {
			return nil, err
		}
		peers = append(peers, p)
	}
	return peers, rows.Err()
}
