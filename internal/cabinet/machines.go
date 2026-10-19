package cabinet

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sreda/internal/tunnel"
	"sync"
	"time"
)

const connectionCodeLifetime = 15 * time.Minute
const machineContactLifetime = 90 * time.Second

type machineRuntime struct {
	mu      sync.Mutex
	gateway tunnel.Gateway
}

// SetGateway attaches the privileged network boundary. A nil gateway denies enrollment.
// Configure it before serving requests.
func (a *App) SetGateway(gateway tunnel.Gateway) { a.machines.gateway = gateway }

func installMachineSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS machines (
 id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL,
 code_hash BLOB UNIQUE, code_expires_at INTEGER, credential_hash BLOB UNIQUE,
 public_key TEXT UNIQUE, tunnel_address TEXT UNIQUE, proxy_token TEXT,
 enabled INTEGER NOT NULL DEFAULT 0, last_seen INTEGER,
 created_at INTEGER NOT NULL
 ); CREATE INDEX IF NOT EXISTS machines_owner ON machines(owner_id);`)
	return err
}

// MachineConnection is available to trusted gateway routing code, never browser responses.
// ProxyToken authenticates gateway-to-agent traffic and must not be logged.
type MachineConnection struct {
	ID, OwnerID                    int64
	PublicKey, Address, ProxyToken string
	Enabled                        bool
	LastSeen                       time.Time
}

func (a *App) MachineConnection(ctx context.Context, id int64) (MachineConnection, error) {
	var m MachineConnection
	var last sql.NullInt64
	err := a.db.QueryRowContext(ctx, `SELECT id,owner_id,COALESCE(public_key,''),COALESCE(tunnel_address,''),COALESCE(proxy_token,''),enabled,last_seen FROM machines WHERE id=?`, id).Scan(&m.ID, &m.OwnerID, &m.PublicKey, &m.Address, &m.ProxyToken, &m.Enabled, &last)
	if last.Valid {
		m.LastSeen = time.Unix(last.Int64, 0)
	}
	return m, err
}

// SetMachineEnabled revokes the peer before acknowledging disable; enable must be explicit.
func (a *App) SetMachineEnabled(ctx context.Context, id int64, enabled bool) error {
	a.machines.mu.Lock()
	defer a.machines.mu.Unlock()
	m, err := a.MachineConnection(ctx, id)
	if err != nil {
		return err
	}
	if m.PublicKey == "" {
		return errors.New("машина ещё не подключена")
	}
	if a.machines.gateway == nil {
		return errors.New("сетевой шлюз не настроен")
	}
	peer := tunnel.Peer{MachineID: m.ID, PublicKey: m.PublicKey, Address: m.Address}
	if enabled {
		err = a.machines.gateway.ApplyPeer(ctx, peer)
	} else {
		err = a.machines.gateway.RemovePeer(ctx, peer)
	}
	if err != nil {
		return fmt.Errorf("не удалось подтвердить применение сетевых настроек: %w", err)
	}
	_, err = a.db.ExecContext(ctx, "UPDATE machines SET enabled=? WHERE id=?", enabled, id)
	return err
}
