package machine

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

// InstallManualSchema upgrades existing machine rows without changing identity.
func InstallManualSchema(tx *sql.Tx) error {
	rows, err := tx.Query("PRAGMA table_info(machines)")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, notnull, pk int
		var name, kind string
		var fallback any
		if err = rows.Scan(&cid, &name, &kind, &notnull, &fallback, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "mode" {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = tx.Exec("ALTER TABLE machines ADD COLUMN mode TEXT NOT NULL DEFAULT 'agent' CHECK(mode IN('agent','manual'))")
	return err
}

func (s *sqliteStore) createWithMode(ctx context.Context, ownerID int64, name string, mode Mode, code []byte, expiry, created int64) (int64, error) {
	result, err := s.db.ExecContext(ctx, `INSERT INTO machines(id,owner_id,name,code_hash,code_expires_at,created_at,mode)VALUES((SELECT COALESCE(MAX(id),0)+1 FROM (SELECT id FROM machines UNION ALL SELECT id FROM machine_tombstones)),?,?,?,?,?,?)`, ownerID, name, code, expiry, created, mode)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

func (s *sqliteStore) manualParameters(ctx context.Context, actor Actor, id int64) (ManualParameters, error) {
	var p ManualParameters
	err := s.db.QueryRowContext(ctx, `SELECT id,name,COALESCE(public_key,''),COALESCE(tunnel_address,''),enabled FROM machines WHERE id=? AND mode='manual' AND(owner_id=? OR ?)`, id, actor.ID, actor.Admin).Scan(&p.ID, &p.Name, &p.PublicKey, &p.Address, &p.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return p, failure(NotFound, "Машина не найдена")
	}
	return p, err
}

func (s *sqliteStore) manualCode(ctx context.Context, id int64, hash []byte, now int64) error {
	var found int
	err := s.db.QueryRowContext(ctx, `SELECT 1 FROM machines WHERE id=? AND mode='manual' AND code_hash=? AND code_expires_at>? AND credential_hash IS NULL`, id, hash, now).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return failure(Unauthorized, "Код недействителен или уже использован")
	}
	return err
}

func (s *sqliteStore) recordHandshake(ctx context.Context, c Connection, latest time.Time) error {
	var seen any
	if !latest.IsZero() {
		seen = latest.Unix()
	}
	result, err := s.db.ExecContext(ctx, `UPDATE machines SET last_seen=? WHERE id=? AND mode='manual' AND public_key=? AND enabled=1`, seen, c.ID, c.PublicKey)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return failure(Unavailable, "Подключение изменилось во время наблюдения")
	}
	return nil
}
