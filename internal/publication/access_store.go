package publication

import (
	"context"
	"database/sql"
	"errors"
)

type accessCandidate struct {
	Publication
	MachineEnabled bool
	Delivery       Connection
}
type accessDecision struct {
	Change, Enabled bool
	State           string
}

func (s *sqliteStore) changeAccess(ctx context.Context, id string, decide func(accessCandidate) (accessDecision, error)) (Publication, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Publication{}, err
	}
	defer tx.Rollback()
	p, err := scanPublication(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM publications p JOIN machines m ON m.id=p.machine_id JOIN users u ON u.id=m.owner_id WHERE p.id=?`, id))
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return p, err
	}
	candidate := accessCandidate{Publication: p}
	if p.ID != "" {
		candidate.Delivery = Connection{ID: p.ID, MachineID: p.MachineID, Target: p.Target}
		if err = tx.QueryRowContext(ctx, `SELECT enabled,mode,COALESCE(tunnel_address,''),COALESCE(proxy_token,'') FROM machines WHERE id=?`, p.MachineID).Scan(&candidate.MachineEnabled, &candidate.Delivery.Mode, &candidate.Delivery.Address, &candidate.Delivery.ProxyToken); err != nil {
			return p, err
		}
	}
	decision, err := decide(candidate)
	if err != nil {
		return p, err
	}
	if !decision.Change {
		return p, nil
	}
	if _, err = tx.ExecContext(ctx, `UPDATE machine_control SET generation=generation+1 WHERE machine_id=?`, p.MachineID); err != nil {
		return p, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE publications SET desired_enabled=?,state=?,error='',revision=revision+1,generation=(SELECT generation FROM machine_control WHERE machine_id=?) WHERE id=?`, decision.Enabled, decision.State, p.MachineID, p.ID)
	if err != nil {
		return p, err
	}
	if err = tx.Commit(); err != nil {
		return p, err
	}
	p.DesiredEnabled = decision.Enabled
	p.State = decision.State
	p.Error = ""
	p.Revision++
	return p, nil
}
func (s *sqliteStore) finishAccess(ctx context.Context, id string, revision int64, state, message string) error {
	_, err := s.db.ExecContext(ctx, `UPDATE publications SET state=?,error=? WHERE id=? AND revision=? AND desired_enabled=0`, state, message, id, revision)
	return err
}
