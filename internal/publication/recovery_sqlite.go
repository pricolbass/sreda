package publication

import (
	"context"
	"database/sql"
	"time"
)

func installRecoverySchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS publication_recovery(publication_id TEXT PRIMARY KEY REFERENCES publications(id) ON DELETE CASCADE,last_attempt INTEGER NOT NULL);`)
	return err
}

const pendingClosurePredicate = `p.desired_enabled=0 AND ((NOT EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=p.id) AND p.state<>'Отключена') OR EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=p.id AND d.gateway_closed=0))`

func (s *sqliteStore) pendingClosures(ctx context.Context) ([]Publication, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT p.id,p.revision,EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=p.id) FROM publications p LEFT JOIN publication_recovery r ON r.publication_id=p.id WHERE `+pendingClosurePredicate+` ORDER BY COALESCE(r.last_attempt,0),p.id LIMIT 8`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Publication
	for rows.Next() {
		var p Publication
		if err := rows.Scan(&p.ID, &p.Revision, &p.DeletionPending); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}
func (s *sqliteStore) claimClosure(ctx context.Context, id string, revision int64) (bool, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO publication_recovery(publication_id,last_attempt) SELECT p.id,? FROM publications p WHERE p.id=? AND p.revision=? AND `+pendingClosurePredicate+` ON CONFLICT(publication_id) DO UPDATE SET last_attempt=excluded.last_attempt`, time.Now().UnixNano(), id, revision)
	if err != nil {
		return false, err
	}
	n, err := result.RowsAffected()
	return n == 1, err
}

func (s *sqliteStore) pendingManualConfirmations(ctx context.Context) ([]manualConfirmationCandidate, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT m.id,m.access_revision,u.access_revision,m.mode,m.enabled,m.desired_enabled,u.blocked,EXISTS(SELECT 1 FROM machine_connection_ops o WHERE o.machine_id=m.id) OR EXISTS(SELECT 1 FROM machine_enrollments e WHERE e.machine_id=m.id) OR EXISTS(SELECT 1 FROM machine_deletions d WHERE d.machine_id=m.id) OR EXISTS(SELECT 1 FROM machine_reconnections r WHERE r.machine_id=m.id) FROM machines m JOIN users u ON u.id=m.owner_id WHERE EXISTS(SELECT 1 FROM publications p WHERE p.machine_id=m.id AND p.desired_enabled=1 AND p.state='Настраивается' AND NOT EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=p.id))`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []manualConfirmationCandidate
	for rows.Next() {
		var c manualConfirmationCandidate
		if err := rows.Scan(&c.Identity.MachineID, &c.Identity.Revision, &c.Identity.OwnerRevision, &c.Mode, &c.Enabled, &c.DesiredEnabled, &c.OwnerBlocked, &c.PendingOperation); err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}
	return candidates, rows.Err()
}
