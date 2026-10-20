package publication

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"
)

func installDeletionSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS publication_deletions(publication_id TEXT PRIMARY KEY REFERENCES publications(id),removal_generation INTEGER NOT NULL,gateway_closed INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS publication_tombstones(id TEXT PRIMARY KEY,owner_id INTEGER NOT NULL,subdomain TEXT NOT NULL,deleted_at INTEGER NOT NULL);
 CREATE TRIGGER IF NOT EXISTS publication_id_no_reuse BEFORE INSERT ON publications WHEN EXISTS(SELECT 1 FROM publication_tombstones WHERE id=NEW.id) BEGIN SELECT RAISE(ABORT,'publication id was deleted'); END;`)
	return err
}
func (s *sqliteStore) beginDeletion(ctx context.Context, id string, decide func(Publication, bool) (bool, error)) (Publication, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Publication{}, false, err
	}
	defer tx.Rollback()
	p, err := scanPublication(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM publications p JOIN machines m ON m.id=p.machine_id JOIN users u ON u.id=m.owner_id WHERE p.id=?`, id))
	deleted := false
	if errors.Is(err, sql.ErrNoRows) {
		err = tx.QueryRowContext(ctx, "SELECT id,owner_id,subdomain FROM publication_tombstones WHERE id=?", id).Scan(&p.ID, &p.OwnerID, &p.Subdomain)
		deleted = err == nil
	}
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return p, false, err
	}
	change, err := decide(p, deleted)
	if err != nil {
		return p, false, err
	}
	if deleted {
		return p, true, nil
	}
	if !change {
		return p, false, nil
	}
	if _, err = tx.ExecContext(ctx, "UPDATE machine_control SET generation=generation+1 WHERE machine_id=?", p.MachineID); err != nil {
		return p, false, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE publications SET desired_enabled=0,state='Удаляется',error='',revision=revision+1,generation=(SELECT generation FROM machine_control WHERE machine_id=?) WHERE id=?`, p.MachineID, p.ID); err != nil {
		return p, false, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO publication_deletions(publication_id,removal_generation) SELECT id,generation FROM publications WHERE id=?`, p.ID); err != nil {
		return p, false, err
	}
	if err = tx.Commit(); err != nil {
		return p, false, err
	}
	p.DeletionPending = true
	p.DesiredEnabled = false
	p.State = "Удаляется"
	p.Revision++
	return p, false, nil
}
func (s *sqliteStore) recordDeletionClosure(ctx context.Context, id string, closed bool, message string) (bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "UPDATE publication_deletions SET gateway_closed=? WHERE publication_id=?", closed, id); err != nil {
		return false, err
	}
	if _, err = tx.ExecContext(ctx, "UPDATE publications SET state='Удаляется',error=? WHERE id=? AND EXISTS(SELECT 1 FROM publication_deletions WHERE publication_id=?)", message, id, id); err != nil {
		return false, err
	}
	if err = finalizeDeletions(ctx, tx, 0); err != nil {
		return false, err
	}
	var count int
	if err = tx.QueryRowContext(ctx, "SELECT COUNT(*) FROM publication_tombstones WHERE id=?", id).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, tx.Commit()
}
func finalizeDeletions(ctx context.Context, tx *sql.Tx, machineID int64) error {
	rows, err := tx.QueryContext(ctx, `SELECT p.id,m.owner_id,p.subdomain FROM publication_deletions d JOIN publications p ON p.id=d.publication_id JOIN machines m ON m.id=p.machine_id JOIN machine_control c ON c.machine_id=m.id WHERE d.gateway_closed=1 AND (m.mode='manual' OR c.applied_generation>=d.removal_generation) AND (?=0 OR m.id=?)`, machineID, machineID)
	if err != nil {
		return err
	}
	type tombstone struct {
		id, label string
		owner     int64
	}
	var ready []tombstone
	for rows.Next() {
		var item tombstone
		if err := rows.Scan(&item.id, &item.owner, &item.label); err != nil {
			rows.Close()
			return err
		}
		ready = append(ready, item)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	for _, item := range ready {
		if _, err = tx.ExecContext(ctx, "INSERT INTO publication_tombstones(id,owner_id,subdomain,deleted_at) VALUES(?,?,?,?)", item.id, item.owner, item.label, time.Now().Unix()); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM publication_deletions WHERE publication_id=?", item.id); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "DELETE FROM publications WHERE id=?", item.id); err != nil {
			return err
		}
	}
	return nil
}

// Only derived control metadata cascades; publications themselves remain RESTRICT.
func installControlCascade(tx *sql.Tx) error {
	var schema string
	if err := tx.QueryRow("SELECT sql FROM sqlite_schema WHERE name='machine_control'").Scan(&schema); err != nil {
		return err
	}
	if strings.Contains(strings.ToUpper(schema), "ON DELETE CASCADE") {
		return nil
	}
	_, err := tx.Exec(`CREATE TABLE machine_control_cascade(machine_id INTEGER PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,generation INTEGER NOT NULL DEFAULT 0,applied_generation INTEGER NOT NULL DEFAULT 0);
 INSERT INTO machine_control_cascade SELECT machine_id,generation,applied_generation FROM machine_control;
 DROP TABLE machine_control;ALTER TABLE machine_control_cascade RENAME TO machine_control;`)
	return err
}
