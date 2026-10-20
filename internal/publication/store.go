package publication

import (
	"context"
	"database/sql"
	"errors"
	"sreda/internal/agentprotocol"
	"sreda/internal/machine"
	"time"
)

type sqliteStore struct{ db *sql.DB }

func InstallSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS machine_control(machine_id INTEGER PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,generation INTEGER NOT NULL DEFAULT 0,applied_generation INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS publications(id TEXT PRIMARY KEY,machine_id INTEGER NOT NULL REFERENCES machines(id),subdomain TEXT NOT NULL UNIQUE,target TEXT NOT NULL,desired_enabled INTEGER NOT NULL DEFAULT 1,state TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL,revision INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS publications_machine ON publications(machine_id);`)
	if err != nil {
		return err
	}
	if err := installControlCascade(tx); err != nil {
		return err
	}
	return installDeletionSchema(tx)
}
func (s *sqliteStore) zone(ctx context.Context) (string, error) {
	var zone string
	err := s.db.QueryRowContext(ctx, "SELECT value FROM settings WHERE key='publication_zone'").Scan(&zone)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil
	}
	return zone, err
}
func (s *sqliteStore) saveZone(ctx context.Context, zone string) (string, error) {
	if _, err := s.db.ExecContext(ctx, "INSERT OR IGNORE INTO settings(key,value) VALUES('publication_zone',?)", zone); err != nil {
		return "", err
	}
	return s.zone(ctx)
}

const columns = `p.id,p.machine_id,p.subdomain,p.target,p.state,p.error,p.revision,u.login,m.owner_id,p.desired_enabled,EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=p.id)`

func scanPublication(row interface{ Scan(...any) error }) (Publication, error) {
	var p Publication
	err := row.Scan(&p.ID, &p.MachineID, &p.Subdomain, &p.Target, &p.State, &p.Error, &p.Revision, &p.Owner, &p.OwnerID, &p.DesiredEnabled, &p.DeletionPending)
	return p, err
}
func (s *sqliteStore) get(ctx context.Context, actor Actor, id string) (Publication, error) {
	p, err := scanPublication(s.db.QueryRowContext(ctx, `SELECT `+columns+` FROM publications p JOIN machines m ON m.id=p.machine_id JOIN users u ON u.id=m.owner_id WHERE p.id=? AND (m.owner_id=? OR ?)`, id, actor.ID, actor.Admin))
	if errors.Is(err, sql.ErrNoRows) {
		return p, fail(NotFound, "Публикация не найдена")
	}
	return p, err
}
func (s *sqliteStore) view(ctx context.Context, actor Actor) (View, error) {
	view := View{Publications: []Publication{}, Machines: []Machine{}}
	rows, err := s.db.QueryContext(ctx, `SELECT `+columns+` FROM publications p JOIN machines m ON m.id=p.machine_id JOIN users u ON u.id=m.owner_id WHERE m.owner_id=? OR ? ORDER BY p.created_at,p.id`, actor.ID, actor.Admin)
	if err != nil {
		return view, err
	}
	for rows.Next() {
		p, err := scanPublication(rows)
		if err != nil {
			rows.Close()
			return view, err
		}
		view.Publications = append(view.Publications, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return view, err
	}
	rows, err = s.db.QueryContext(ctx, "SELECT id,name FROM machines WHERE owner_id=? AND enabled=1 ORDER BY id", actor.ID)
	if err != nil {
		return view, err
	}
	defer rows.Close()
	for rows.Next() {
		var m Machine
		if err := rows.Scan(&m.ID, &m.Name); err != nil {
			return view, err
		}
		view.Machines = append(view.Machines, m)
	}
	return view, rows.Err()
}

// The store controls atomic SQLite transactions. Product policy callbacks are
// supplied by the module and evaluated against the locked persisted snapshot.
type machineEligibility struct {
	ID, OwnerID         int64
	Login               string
	Enabled, Enrolled   bool
	Mode                machine.Mode
	Address, ProxyToken string
}
type creationDecision struct {
	Publication Publication
	Existing    bool
}

func (s *sqliteStore) schedule(ctx context.Context, input CreateRequest, decide func(machineEligibility, *Publication) (creationDecision, error)) (Publication, bool, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return Publication{}, false, err
	}
	defer tx.Rollback()
	var machine machineEligibility
	var key sql.NullString
	err = tx.QueryRowContext(ctx, "SELECT m.id,m.owner_id,m.enabled,m.public_key,u.login,m.mode,COALESCE(m.tunnel_address,''),COALESCE(m.proxy_token,'') FROM machines m JOIN users u ON u.id=m.owner_id WHERE m.id=? AND u.blocked=0", input.MachineID).Scan(&machine.ID, &machine.OwnerID, &machine.Enabled, &key, &machine.Login, &machine.Mode, &machine.Address, &machine.ProxyToken)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Publication{}, false, err
	}
	machine.Enrolled = key.Valid
	old, err := scanPublication(tx.QueryRowContext(ctx, `SELECT `+columns+` FROM publications p JOIN machines m ON m.id=p.machine_id JOIN users u ON u.id=m.owner_id WHERE p.subdomain=?`, input.Subdomain))
	var existing *Publication
	if err == nil {
		existing = &old
	} else if !errors.Is(err, sql.ErrNoRows) {
		return Publication{}, false, err
	}
	decision, err := decide(machine, existing)
	if err != nil {
		return Publication{}, false, err
	}
	p := decision.Publication
	if decision.Existing {
		return p, false, nil
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO machine_control(machine_id) VALUES(?)", input.MachineID); err == nil {
		_, err = tx.ExecContext(ctx, "UPDATE machine_control SET generation=generation+1 WHERE machine_id=?", input.MachineID)
	}
	if err != nil {
		return Publication{}, false, err
	}
	var generation uint64
	if err = tx.QueryRowContext(ctx, "SELECT generation FROM machine_control WHERE machine_id=?", input.MachineID).Scan(&generation); err != nil {
		return Publication{}, false, err
	}
	if _, err = tx.ExecContext(ctx, "INSERT INTO publications(id,machine_id,subdomain,target,state,generation,created_at) VALUES(?,?,?,?,?,?,?)", p.ID, p.MachineID, p.Subdomain, p.Target, p.State, generation, time.Now().Unix()); err != nil {
		return Publication{}, false, err
	}
	if err = tx.Commit(); err != nil {
		return Publication{}, false, err
	}
	return p, true, nil
}

type retryCandidate struct {
	OwnerID, MachineID int64
	Desired, Enabled   bool
	State              string
}

func (s *sqliteStore) retry(ctx context.Context, id, nextState string, decide func(retryCandidate) (bool, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var candidate retryCandidate
	err = tx.QueryRowContext(ctx, `SELECT m.owner_id,p.machine_id,p.state,p.desired_enabled,m.enabled FROM publications p JOIN machines m ON m.id=p.machine_id WHERE p.id=? AND EXISTS(SELECT 1 FROM users u WHERE u.id=m.owner_id AND u.blocked=0)`, id).Scan(&candidate.OwnerID, &candidate.MachineID, &candidate.State, &candidate.Desired, &candidate.Enabled)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	retry, err := decide(candidate)
	if err != nil {
		return err
	}
	if !retry {
		return nil
	}
	if _, err = tx.ExecContext(ctx, "UPDATE machine_control SET generation=generation+1 WHERE machine_id=?", candidate.MachineID); err == nil {
		_, err = tx.ExecContext(ctx, "UPDATE publications SET state=?,error='',generation=(SELECT generation FROM machine_control WHERE machine_id=?) WHERE id=?", nextState, candidate.MachineID, id)
	}
	if err != nil {
		return err
	}
	return tx.Commit()
}
func (s *sqliteStore) control(ctx context.Context, machineID int64) (uint64, []agentprotocol.Route, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return 0, nil, err
	}
	defer tx.Rollback()
	if err := activeMachine(ctx, tx, machineID); err != nil {
		return 0, nil, err
	}
	var generation uint64
	err = tx.QueryRowContext(ctx, "SELECT generation FROM machine_control WHERE machine_id=?", machineID).Scan(&generation)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return 0, nil, err
	}
	routes := []agentprotocol.Route{}
	rows, err := tx.QueryContext(ctx, "SELECT id,target,desired_enabled FROM publications WHERE machine_id=? AND NOT EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=publications.id) ORDER BY id", machineID)
	if err != nil {
		return 0, nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var route agentprotocol.Route
		if err := rows.Scan(&route.ID, &route.Target, &route.Enabled); err != nil {
			return 0, nil, err
		}
		routes = append(routes, route)
	}
	return generation, routes, rows.Err()
}

type acknowledgmentPlan struct {
	Ready, Failed           bool
	ReadyState, FailedState string
}

func (s *sqliteStore) acknowledge(ctx context.Context, machineID int64, ack Acknowledgment, decide func(uint64, uint64) (acknowledgmentPlan, error)) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := activeMachine(ctx, tx, machineID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO machine_control(machine_id) VALUES(?)", machineID); err != nil {
		return err
	}
	var generation, previous uint64
	if err = tx.QueryRowContext(ctx, "SELECT generation,applied_generation FROM machine_control WHERE machine_id=?", machineID).Scan(&generation, &previous); err != nil {
		return err
	}
	plan, err := decide(generation, previous)
	if err != nil {
		return err
	}
	if plan.Ready {
		if _, err = tx.ExecContext(ctx, "UPDATE machine_control SET applied_generation=? WHERE machine_id=?", ack.Applied, machineID); err == nil {
			_, err = tx.ExecContext(ctx, "UPDATE publications SET state=?,error='' WHERE machine_id=? AND desired_enabled=1 AND generation<=?", plan.ReadyState, machineID, ack.Applied)
		}
		if err != nil {
			return err
		}
	}
	if plan.Failed {
		if _, err = tx.ExecContext(ctx, "UPDATE publications SET state=?,error=? WHERE machine_id=? AND generation>? AND generation<=? AND desired_enabled=1", plan.FailedState, ack.Error, machineID, ack.Applied, ack.Failed); err != nil {
			return err
		}
	}
	if plan.Failed {
		if _, err = tx.ExecContext(ctx, `UPDATE publications SET state='Удаляется',error=? WHERE machine_id=? AND EXISTS(SELECT 1 FROM publication_deletions d WHERE d.publication_id=publications.id AND d.removal_generation<=?)`, ack.Error, machineID, ack.Failed); err != nil {
			return err
		}
	}
	if err = finalizeDeletions(ctx, tx, machineID); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *sqliteStore) connection(ctx context.Context, label string) (Connection, error) {
	var c Connection
	var last sql.NullInt64
	err := s.db.QueryRowContext(ctx, `SELECT p.id,p.state,p.desired_enabled,m.id,m.enabled,m.tunnel_address,m.proxy_token,m.last_seen,p.target,m.mode FROM publications p JOIN machines m ON m.id=p.machine_id WHERE p.subdomain=? AND EXISTS(SELECT 1 FROM users u WHERE u.id=m.owner_id AND u.blocked=0)`, label).Scan(&c.ID, &c.State, &c.Desired, &c.MachineID, &c.Enabled, &c.Address, &c.ProxyToken, &last, &c.Target, &c.Mode)
	if last.Valid {
		c.LastSeen = last.Int64
	}
	if errors.Is(err, sql.ErrNoRows) {
		return c, fail(NotFound, "Публикация не найдена")
	}
	return c, err
}

func activeMachine(ctx context.Context, tx *sql.Tx, machineID int64) error {
	var id int64
	err := tx.QueryRowContext(ctx, `SELECT m.id FROM machines m JOIN users u ON u.id=m.owner_id WHERE m.id=? AND m.enabled=1 AND u.blocked=0`, machineID).Scan(&id)
	if errors.Is(err, sql.ErrNoRows) {
		return fail(Unavailable, "Подключение отключено или отозвано")
	}
	return err
}
