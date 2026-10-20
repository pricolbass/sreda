package cabinet

import (
	"context"
	"database/sql"
	"errors"
	"sreda/internal/machine"
	"sreda/internal/tunnel"
	"time"
)

func installMachineSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS machines (
 id INTEGER PRIMARY KEY, owner_id INTEGER NOT NULL REFERENCES users(id), name TEXT NOT NULL,
 code_hash BLOB UNIQUE, code_expires_at INTEGER, credential_hash BLOB UNIQUE,
 public_key TEXT UNIQUE, tunnel_address TEXT UNIQUE, proxy_token TEXT,
 enabled INTEGER NOT NULL DEFAULT 0, last_seen INTEGER,
 created_at INTEGER NOT NULL
 ); CREATE INDEX IF NOT EXISTS machines_owner ON machines(owner_id);
 CREATE TABLE IF NOT EXISTS machine_enrollments(
 machine_id INTEGER PRIMARY KEY REFERENCES machines(id), code_hash BLOB NOT NULL UNIQUE,
 credential_hash BLOB NOT NULL UNIQUE, public_key TEXT NOT NULL UNIQUE,
 tunnel_address TEXT NOT NULL UNIQUE, proxy_token TEXT NOT NULL,
 phase TEXT NOT NULL CHECK(phase IN ('applying','cleanup')),
 lease_owner TEXT NOT NULL,lease_until INTEGER NOT NULL,last_attempt INTEGER NOT NULL DEFAULT 0
 );`)
	if err != nil {
		return err
	}
	if err := machine.InstallManualSchema(tx); err != nil {
		return err
	}
	if err := machine.InstallDeletionSchema(tx); err != nil {
		return err
	}
	if err := machine.InstallAccessSchema(tx); err != nil {
		return err
	}
	if err := machine.InstallReconnectionSchema(tx); err != nil {
		return err
	}
	return machine.InstallRecoverySchema(tx)
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

// ReconcileMachinePeers gives each ordered phase its own bounded opportunity.
// All phase contexts inherit the caller's cancellation; production supplies the
// server lifetime, so an expired phase cannot consume the next phase's budget.
func (a *App) ReconcileMachinePeers(ctx context.Context) error {
	accessCtx, cancelAccess := context.WithTimeout(ctx, reconciliationPhaseTimeout)
	accessErr := a.access.Resume(accessCtx)
	cancelAccess()

	publicationCtx, cancelPublication := context.WithTimeout(ctx, reconciliationPhaseTimeout)
	publicationErr := a.publications.Reconcile(publicationCtx)
	cancelPublication()

	var machineErr, manualErr error
	if _, configured := a.machines.GatewayDetails(); configured {
		machineCtx, cancelMachine := context.WithTimeout(ctx, reconciliationPhaseTimeout)
		machineErr = a.machines.Reconcile(machineCtx)
		cancelMachine()

		manualCtx, cancelManual := context.WithTimeout(ctx, reconciliationPhaseTimeout)
		manualErr = a.publications.ReconcileManual(manualCtx)
		cancelManual()
	}
	return errors.Join(accessErr, publicationErr, machineErr, manualErr)
}

const reconciliationPhaseTimeout = 20 * time.Second
