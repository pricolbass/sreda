package cabinet

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"regexp"
	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"strings"
	"sync"
)

type publicationRuntime struct {
	mu     sync.Mutex
	zone   string
	routes map[string]*publicationRoute
	dial   func(context.Context, string, string) (net.Conn, error)
}

func installPublicationSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS machine_control(machine_id INTEGER PRIMARY KEY REFERENCES machines(id),generation INTEGER NOT NULL DEFAULT 0,applied_generation INTEGER NOT NULL DEFAULT 0);
 CREATE TABLE IF NOT EXISTS publications(id TEXT PRIMARY KEY,machine_id INTEGER NOT NULL REFERENCES machines(id),subdomain TEXT NOT NULL UNIQUE,target TEXT NOT NULL,desired_enabled INTEGER NOT NULL DEFAULT 1,state TEXT NOT NULL,error TEXT NOT NULL DEFAULT '',generation INTEGER NOT NULL,revision INTEGER NOT NULL DEFAULT 1,created_at INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS publications_machine ON publications(machine_id);`)
	return err
}

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var subdomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// ConfigurePublicationZone sets an explicit, persistent common domain zone.
// It is immutable after first configuration, preventing silent URL changes.
func (a *App) ConfigurePublicationZone(zone string) error {
	if len(zone) > 253 || !domainPattern.MatchString(zone) {
		return errors.New("укажите общую доменную зону строчными буквами, без https и пути")
	}
	a.publications.mu.Lock()
	defer a.publications.mu.Unlock()
	var saved string
	err := a.db.QueryRow("SELECT value FROM settings WHERE key='publication_zone'").Scan(&saved)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if saved != "" && saved != zone {
		return errors.New("доменная зона отличается от сохранённой")
	}
	if _, err = a.db.Exec("INSERT OR IGNORE INTO settings(key,value) VALUES('publication_zone',?)", zone); err != nil {
		return err
	}
	a.publications.zone = zone
	return nil
}

// SetPublicationDialer replaces only the external tunnel network boundary before serving.
// Production defaults to a direct dial of the fixed assigned machine address.
func (a *App) SetPublicationDialer(dial func(context.Context, string, string) (net.Conn, error)) {
	a.publications.dial = dial
}

type Publication struct {
	ID        string `json:"id"`
	MachineID int64  `json:"machine_id"`
	Subdomain string `json:"subdomain"`
	Target    string `json:"target"`
	URL       string `json:"url"`
	State     string `json:"state"`
	Error     string `json:"error"`
	Revision  int64  `json:"revision"`
	Owner     string `json:"owner"`
}

func (a *App) publicationFromRow(row *sql.Row) (Publication, error) {
	var p Publication
	err := row.Scan(&p.ID, &p.MachineID, &p.Subdomain, &p.Target, &p.State, &p.Error, &p.Revision, &p.Owner)
	p.URL = "https://" + p.Subdomain + "." + a.publications.zone
	return p, err
}

const publicationColumns = `p.id,p.machine_id,p.subdomain,p.target,p.state,p.error,p.revision,u.login`

func (a *App) controlFor(m MachineConnection) (AgentControl, error) {
	c := AgentControl{MachineID: m.ID, Address: m.Address, Tunnel: a.machines.gateway.Details(), ProxyToken: m.ProxyToken, Routes: []AgentRoute{}}
	err := a.db.QueryRow("SELECT generation FROM machine_control WHERE machine_id=?", m.ID).Scan(&c.Generation)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return c, err
	}
	rows, err := a.db.Query("SELECT id,target,desired_enabled FROM publications WHERE machine_id=? ORDER BY id", m.ID)
	if err != nil {
		return c, err
	}
	defer rows.Close()
	for rows.Next() {
		var route agentprotocol.Route
		if err := rows.Scan(&route.ID, &route.Target, &route.Enabled); err != nil {
			return c, err
		}
		c.Routes = append(c.Routes, route)
	}
	return c, rows.Err()
}
func (a *App) recordAgentAcknowledgment(ctx context.Context, machineID int64, applied, failed uint64, applyError string) error {
	if applied > 1<<62 || failed > 1<<62 {
		return errors.New("недопустимая версия маршрутов")
	}
	tx, err := a.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, "INSERT OR IGNORE INTO machine_control(machine_id) VALUES(?)", machineID); err != nil {
		return err
	}
	var generation, previous uint64
	if err = tx.QueryRowContext(ctx, "SELECT generation,applied_generation FROM machine_control WHERE machine_id=?", machineID).Scan(&generation, &previous); err != nil {
		return err
	}
	if applied > generation || failed > generation {
		return errors.New("неизвестная версия маршрутов")
	}
	if applied >= previous {
		if _, err = tx.ExecContext(ctx, "UPDATE machine_control SET applied_generation=? WHERE machine_id=?", applied, machineID); err != nil {
			return err
		}
		if _, err = tx.ExecContext(ctx, "UPDATE publications SET state='Настроена',error='' WHERE machine_id=? AND desired_enabled=1 AND generation<=?", machineID, applied); err != nil {
			return err
		}
	}
	if failed > applied && failed > previous && failed == generation {
		if applyError == "" {
			applyError = "Агент не подтвердил применение маршрутов"
		}
		if len(applyError) > 300 {
			applyError = "Агент не смог применить маршруты"
		}
		if _, err = tx.ExecContext(ctx, "UPDATE publications SET state='Ошибка',error=? WHERE machine_id=? AND generation>? AND generation<=? AND desired_enabled=1", applyError, machineID, applied, failed); err != nil {
			return err
		}
	}
	return tx.Commit()
}
func validatePublicationTarget(target string) error { return agent.ValidateTargetSyntax(target) }
func (a *App) reservedSubdomain(label string) bool {
	host := a.host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return label+"."+a.publications.zone == strings.ToLower(host)
}
