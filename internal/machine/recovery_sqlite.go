package machine

import (
	"context"
	"database/sql"
	"sreda/internal/tunnel"
	"time"
)

func InstallRecoverySchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS machine_recovery(machine_id INTEGER PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,last_attempt INTEGER NOT NULL);`)
	return err
}
func (s *sqliteStore) recordRecoveryAttempt(ctx context.Context, id int64) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO machine_recovery(machine_id,last_attempt)VALUES(?,?) ON CONFLICT(machine_id) DO UPDATE SET last_attempt=excluded.last_attempt`, id, time.Now().UnixNano())
	return err
}

type recoveryPeer struct {
	peer    tunnel.Peer
	enabled bool
}

func (s *sqliteStore) recoveryPeers(ctx context.Context) ([]recoveryPeer, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.id,m.public_key,m.tunnel_address,m.desired_enabled=1 AND u.blocked=0 FROM machines m JOIN users u ON u.id=m.owner_id LEFT JOIN machine_recovery r ON r.machine_id=m.id WHERE m.public_key IS NOT NULL AND NOT EXISTS(SELECT 1 FROM machine_connection_ops o WHERE o.machine_id=m.id) AND NOT EXISTS(SELECT 1 FROM machine_deletions d WHERE d.machine_id=m.id) ORDER BY COALESCE(r.last_attempt,0),m.id LIMIT 100`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []recoveryPeer
	for rows.Next() {
		var c recoveryPeer
		if err := rows.Scan(&c.peer.MachineID, &c.peer.PublicKey, &c.peer.Address, &c.enabled); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
