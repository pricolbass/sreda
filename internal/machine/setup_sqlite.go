package machine

import (
	"context"
	"database/sql"
	"errors"
)

func (s *sqliteStore) setupParameters(ctx context.Context, ownerID, id int64) (SetupParameters, error) {
	var p SetupParameters
	err := s.db.QueryRowContext(ctx, `SELECT id,name,mode,COALESCE(tunnel_address,'') FROM machines WHERE id=? AND owner_id=?`, id, ownerID).Scan(&p.ID, &p.Name, &p.Mode, &p.Address)
	if errors.Is(err, sql.ErrNoRows) {
		return p, failure(NotFound, "Машина не найдена")
	}
	return p, err
}
