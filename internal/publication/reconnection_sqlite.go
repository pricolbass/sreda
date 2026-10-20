package publication

import (
	"context"
	"database/sql"
	"errors"
	"sreda/internal/agentprotocol"
)

func (s *sqliteStore) suspendMachine(ctx context.Context, id, revision, ownerRevision int64) ([]Publication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var found int64
	err = tx.QueryRowContext(ctx, `SELECT m.id FROM machines m JOIN users u ON u.id=m.owner_id WHERE m.id=? AND m.enabled=0 AND m.access_revision=? AND u.access_revision=? AND u.blocked=0 AND EXISTS(SELECT 1 FROM machine_reconnections x WHERE x.machine_id=m.id)`, id, revision, ownerRevision).Scan(&found)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fail(Conflict, "Подключение изменилось")
	}
	if err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO machine_control(machine_id,generation,applied_generation)VALUES(?,1,0)ON CONFLICT(machine_id)DO UPDATE SET generation=generation+1,applied_generation=0`, id); err != nil {
		return nil, err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE publications SET state=CASE WHEN desired_enabled=1 AND NOT EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=publications.id) THEN 'Настраивается' ELSE state END,revision=revision+1,generation=(SELECT generation FROM machine_control WHERE machine_id=?) WHERE machine_id=?`, id, id); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id FROM publications WHERE machine_id=?`, id)
	if err != nil {
		return nil, err
	}
	var pubs []Publication
	for rows.Next() {
		var p Publication
		if err = rows.Scan(&p.ID); err != nil {
			rows.Close()
			return nil, err
		}
		pubs = append(pubs, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return pubs, tx.Commit()
}

func (s *sqliteStore) confirmManual(ctx context.Context, identity agentprotocol.ConnectionIdentity) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := activeMachine(ctx, tx, identity); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE publications SET state='Настроена',error='' WHERE machine_id=? AND desired_enabled=1 AND EXISTS(SELECT 1 FROM machines m WHERE m.id=publications.machine_id AND m.mode='manual') AND NOT EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=publications.id)`, identity.MachineID); err != nil {
		return err
	}
	return tx.Commit()
}
