package machine

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

type deletionCandidate struct {
	ID, OwnerID  int64
	Name         string
	Publications []BlockingPublication
}
type deletionIntent struct {
	connection Connection
	owner      string
	waiting    bool
	enrollment *enrollmentIntent
	operation  *connectionOperation
}

func InstallDeletionSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS machine_deletions(machine_id INTEGER PRIMARY KEY REFERENCES machines(id),lease_owner TEXT NOT NULL,lease_until INTEGER NOT NULL,error TEXT NOT NULL DEFAULT '',last_attempt INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS machine_tombstones(id INTEGER PRIMARY KEY,owner_id INTEGER NOT NULL,name TEXT NOT NULL,deleted_at INTEGER NOT NULL);
 CREATE TABLE IF NOT EXISTS machine_connection_ops(machine_id INTEGER PRIMARY KEY REFERENCES machines(id),desired_enabled INTEGER NOT NULL,phase TEXT NOT NULL,lease_owner TEXT NOT NULL,lease_until INTEGER NOT NULL,last_attempt INTEGER NOT NULL DEFAULT 0);
 CREATE TRIGGER IF NOT EXISTS machine_id_no_reuse BEFORE INSERT ON machines WHEN EXISTS(SELECT 1 FROM machine_tombstones WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'machine id was deleted'); END;`)
	return err
}
func (s *sqliteStore) reserveDeletion(ctx context.Context, id int64, owner string, now time.Time, decide func(deletionCandidate) error) (deletionIntent, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return deletionIntent{}, false, err
	}
	defer tx.Rollback()
	var candidate deletionCandidate
	var intent deletionIntent
	err = tx.QueryRowContext(ctx, `SELECT id,owner_id,name,COALESCE(public_key,''),COALESCE(tunnel_address,'') FROM machines WHERE id=?`, id).Scan(&candidate.ID, &candidate.OwnerID, &candidate.Name, &intent.connection.PublicKey, &intent.connection.Address)
	deleted := false
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, "SELECT id,owner_id,name FROM machine_tombstones WHERE id=?", id).Scan(&candidate.ID, &candidate.OwnerID, &candidate.Name)
		deleted = err == nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return intent, false, err
	}
	rows, err := tx.QueryContext(ctx, "SELECT id,subdomain FROM publications WHERE machine_id=? ORDER BY subdomain", id)
	if err != nil {
		return intent, false, err
	}
	for rows.Next() {
		var p BlockingPublication
		if err = rows.Scan(&p.ID, &p.Subdomain); err != nil {
			rows.Close()
			return intent, false, err
		}
		candidate.Publications = append(candidate.Publications, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return intent, false, err
	}
	if err = decide(candidate); err != nil {
		return intent, false, err
	}
	if deleted {
		return intent, true, nil
	}
	if candidate.ID == 0 {
		return intent, false, failure(NotFound, "Машина не найдена")
	}
	var leaseOwner string
	var leaseUntil int64
	err = tx.QueryRowContext(ctx, "SELECT lease_owner,lease_until FROM machine_deletions WHERE machine_id=?", id).Scan(&leaseOwner, &leaseUntil)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return intent, false, err
	}
	if leaseUntil > now.Unix() {
		return deletionIntent{waiting: true}, false, nil
	}
	intent.connection.ID = id
	intent.connection.OwnerID = candidate.OwnerID
	intent.owner = owner
	if _, err = tx.ExecContext(ctx, `INSERT INTO machine_deletions(machine_id,lease_owner,lease_until,last_attempt) VALUES(?,?,?,?) ON CONFLICT(machine_id) DO UPDATE SET lease_owner=excluded.lease_owner,lease_until=excluded.lease_until,last_attempt=excluded.last_attempt`, id, owner, now.Add(enrollmentLease).Unix(), now.Unix()); err != nil {
		return intent, false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE machines SET enabled=0,credential_hash=NULL,code_hash=NULL,code_expires_at=NULL WHERE id=?", id); err != nil {
		return intent, false, err
	}
	var enrollment enrollmentIntent
	var enrollmentUntil int64
	enrollment.connection.ID = id
	enrollment.owner = owner
	enrollment.phase = "cleanup"
	err = tx.QueryRowContext(ctx, "SELECT public_key,tunnel_address,lease_until FROM machine_enrollments WHERE machine_id=?", id).Scan(&enrollment.connection.PublicKey, &enrollment.connection.Address, &enrollmentUntil)
	if err == nil {
		if enrollmentUntil > now.Unix() {
			intent.waiting = true
		} else {
			if _, err = tx.ExecContext(ctx, "UPDATE machine_enrollments SET phase='cleanup',lease_owner=?,lease_until=? WHERE machine_id=?", owner, now.Add(enrollmentLease).Unix(), id); err != nil {
				return intent, false, err
			}
			intent.enrollment = &enrollment
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return intent, false, err
	}
	var operation connectionOperation
	operation.connection = intent.connection
	operation.owner = owner
	var opUntil int64
	err = tx.QueryRowContext(ctx, "SELECT lease_until FROM machine_connection_ops WHERE machine_id=?", id).Scan(&opUntil)
	if err == nil {
		if opUntil > now.Unix() {
			intent.waiting = true
		} else {
			if _, err = tx.ExecContext(ctx, "UPDATE machine_connection_ops SET phase='cleanup',lease_owner=?,lease_until=? WHERE machine_id=?", owner, now.Add(enrollmentLease).Unix(), id); err != nil {
				return intent, false, err
			}
			intent.operation = &operation
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return intent, false, err
	}
	if intent.waiting {
		if _, err = tx.ExecContext(ctx, "UPDATE machine_deletions SET lease_owner='',lease_until=0,error='Ожидается завершение и очистка выполняемого подключения' WHERE machine_id=?", id); err != nil {
			return intent, false, err
		}
	}
	return intent, false, tx.Commit()
}
func (s *sqliteStore) releaseDeletion(ctx context.Context, intent deletionIntent, message string) error {
	_, err := s.db.ExecContext(ctx, "UPDATE machine_deletions SET lease_owner='',lease_until=0,error=? WHERE machine_id=? AND lease_owner=?", message, intent.connection.ID, intent.owner)
	return err
}
func (s *sqliteStore) finishDeletion(ctx context.Context, intent deletionIntent) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM machine_deletions d JOIN machines m ON m.id=d.machine_id WHERE d.machine_id=? AND d.lease_owner=? AND m.enabled=0 AND NOT EXISTS(SELECT 1 FROM publications WHERE machine_id=m.id) AND NOT EXISTS(SELECT 1 FROM machine_enrollments WHERE machine_id=m.id) AND NOT EXISTS(SELECT 1 FROM machine_connection_ops WHERE machine_id=m.id)`, intent.connection.ID, intent.owner).Scan(&count)
	if err != nil {
		return err
	}
	if count != 1 {
		return failure(Unavailable, "Машина ожидает подтверждения очистки")
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO machine_tombstones(id,owner_id,name,deleted_at) SELECT id,owner_id,name,? FROM machines WHERE id=?", time.Now().Unix(), intent.connection.ID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM machine_deletions WHERE machine_id=? AND lease_owner=?", intent.connection.ID, intent.owner); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "DELETE FROM machines WHERE id=?", intent.connection.ID); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *sqliteStore) pendingDeletions(ctx context.Context) ([]deletionCandidate, error) {
	rows, err := s.db.QueryContext(ctx, "SELECT machine_id FROM machine_deletions WHERE lease_until<=? ORDER BY last_attempt,machine_id LIMIT 2", time.Now().Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var candidates []deletionCandidate
	for rows.Next() {
		var c deletionCandidate
		if err = rows.Scan(&c.ID); err != nil {
			return nil, err
		}
		candidates = append(candidates, c)
	}
	return candidates, rows.Err()
}
