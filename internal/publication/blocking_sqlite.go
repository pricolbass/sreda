package publication

import "context"

func (s *sqliteStore) disableOwner(ctx context.Context, ownerID int64) ([]Publication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `UPDATE machine_control SET generation=generation+1 WHERE machine_id IN(SELECT id FROM machines WHERE owner_id=?)`, ownerID); err != nil {
		return nil, err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE publications SET desired_enabled=0,state=CASE WHEN EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=publications.id) THEN state ELSE 'Отключается' END,error='',revision=revision+1,generation=(SELECT generation FROM machine_control WHERE machine_id=publications.machine_id) WHERE machine_id IN(SELECT id FROM machines WHERE owner_id=?)`, ownerID); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `SELECT id,revision,EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=publications.id) FROM publications WHERE machine_id IN(SELECT id FROM machines WHERE owner_id=?)`, ownerID)
	if err != nil {
		return nil, err
	}
	var out []Publication
	for rows.Next() {
		var p Publication
		if err := rows.Scan(&p.ID, &p.Revision, &p.DeletionPending); err != nil {
			rows.Close()
			return nil, err
		}
		out = append(out, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	return out, tx.Commit()
}
