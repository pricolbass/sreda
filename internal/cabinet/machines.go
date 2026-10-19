package cabinet

import (
	"context"
	"database/sql"
	"sreda/internal/machine"
	"sreda/internal/tunnel"
)

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

// MachineConnection is trusted application metadata; it is never rendered.
type MachineConnection = machine.Connection

func (a *App) SetGateway(gateway tunnel.Gateway) { a.machines.SetGateway(gateway) }
func (a *App) MachineConnection(ctx context.Context, id int64) (MachineConnection, error) {
	return a.machines.Connection(ctx, id)
}
func (a *App) SetMachineEnabled(ctx context.Context, id int64, enabled bool) error {
	return a.machines.SetEnabled(ctx, id, enabled)
}
func (a *App) ReconcileMachinePeers(ctx context.Context) error { return a.machines.Reconcile(ctx) }
