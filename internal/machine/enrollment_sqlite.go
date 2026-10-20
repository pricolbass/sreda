package machine

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
)

type enrollmentIntent struct {
	connection               Connection
	codeHash, credentialHash []byte
	phase, owner             string
}

// reserveEnrollment commits the binding before any network side effect. The
// write transaction allocates across both active and unfinished enrollments.
func (s *sqliteStore) reserveEnrollment(ctx context.Context, input EnrollInput, proxy func(Mode) string, owner string, now, leaseUntil int64, pool []string) (enrollmentIntent, error) {
	var intent enrollmentIntent
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return intent, err
	}
	defer tx.Rollback()
	var expiry int64
	err = tx.QueryRowContext(ctx, `SELECT m.id,m.owner_id,m.code_expires_at,m.mode,u.access_revision FROM machines m JOIN users u ON u.id=m.owner_id WHERE m.code_hash=? AND m.credential_hash IS NULL AND u.blocked=0`, hash(input.Code)).Scan(&intent.connection.ID, &intent.connection.OwnerID, &expiry, &intent.connection.Mode, &intent.connection.OwnerRevision)
	if errors.Is(err, sql.ErrNoRows) {
		return intent, failure(Unauthorized, "Код недействителен или уже использован")
	}
	if err != nil {
		return intent, err
	}
	var lease int64
	err = tx.QueryRowContext(ctx, `SELECT code_hash,credential_hash,public_key,tunnel_address,proxy_token,phase,lease_owner,lease_until FROM machine_enrollments WHERE machine_id=?`, intent.connection.ID).Scan(&intent.codeHash, &intent.credentialHash, &intent.connection.PublicKey, &intent.connection.Address, &intent.connection.ProxyToken, &intent.phase, &intent.owner, &lease)
	if err == nil {
		if !bytes.Equal(intent.credentialHash, hash(input.Credential)) || intent.connection.PublicKey != input.PublicKey {
			return intent, failure(Unauthorized, "Код уже закреплён за другим подключением")
		}
		if lease > now {
			return intent, failure(Unauthorized, "Подключение уже выполняется")
		}
		// An abandoned apply can have changed the kernel; remove it before retry.
		intent.phase = "cleanup"
		intent.owner = owner
		_, err = tx.ExecContext(ctx, `UPDATE machine_enrollments SET phase='cleanup',lease_owner=?,lease_until=?,last_attempt=? WHERE machine_id=?`, owner, leaseUntil, now, intent.connection.ID)
		if err != nil {
			return intent, err
		}
		return intent, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return intent, err
	}
	if expiry <= now {
		return intent, failure(Unauthorized, "Код недействителен или уже использован")
	}
	var count int
	err = tx.QueryRowContext(ctx, `SELECT (SELECT COUNT(*) FROM machines WHERE public_key=?) + (SELECT COUNT(*) FROM machine_enrollments WHERE public_key=?)`, input.PublicKey, input.PublicKey).Scan(&count)
	if err != nil {
		return intent, err
	}
	if count > 0 {
		return intent, failure(Invalid, "Этот публичный ключ уже закреплён за другой машиной")
	}
	rows, err := tx.QueryContext(ctx, `SELECT tunnel_address FROM machines WHERE tunnel_address IS NOT NULL UNION SELECT tunnel_address FROM machine_enrollments`)
	if err != nil {
		return intent, err
	}
	used := map[string]bool{}
	for rows.Next() {
		var address string
		if err := rows.Scan(&address); err != nil {
			rows.Close()
			return intent, err
		}
		used[address] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return intent, err
	}
	for _, address := range pool {
		if !used[address] {
			intent.connection.Address = address
			break
		}
	}
	if intent.connection.Address == "" {
		return intent, failure(Unavailable, "Исчерпан пул из 100 подключений")
	}
	intent.codeHash = hash(input.Code)
	intent.credentialHash = hash(input.Credential)
	intent.connection.PublicKey = input.PublicKey
	intent.connection.ProxyToken = proxy(intent.connection.Mode)
	intent.phase = "applying"
	intent.owner = owner
	_, err = tx.ExecContext(ctx, `INSERT INTO machine_enrollments(machine_id,code_hash,credential_hash,public_key,tunnel_address,proxy_token,phase,lease_owner,lease_until) VALUES(?,?,?,?,?,?,'applying',?,?)`, intent.connection.ID, intent.codeHash, intent.credentialHash, intent.connection.PublicKey, intent.connection.Address, intent.connection.ProxyToken, owner, leaseUntil)
	if err != nil {
		return intent, err
	}
	return intent, tx.Commit()
}
func (s *sqliteStore) finalizeEnrollment(ctx context.Context, intent enrollmentIntent, now int64) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE machines SET code_hash=NULL,code_expires_at=NULL,credential_hash=?,public_key=?,tunnel_address=?,proxy_token=?,enabled=1,desired_enabled=1,access_state='Подключено',access_error='' WHERE id=? AND code_hash=? AND credential_hash IS NULL AND EXISTS(SELECT 1 FROM users u WHERE u.id=machines.owner_id AND u.blocked=0 AND u.access_revision=?) AND EXISTS(SELECT 1 FROM machine_enrollments WHERE machine_id=? AND lease_owner=? AND phase='applying' AND lease_until>?)`, intent.credentialHash, intent.connection.PublicKey, intent.connection.Address, intent.connection.ProxyToken, intent.connection.ID, intent.codeHash, intent.connection.OwnerRevision, intent.connection.ID, intent.owner, now)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return failure(Unavailable, "Подключение ожидает подтверждённой очистки")
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM machine_enrollments WHERE machine_id=? AND lease_owner=?`, intent.connection.ID, intent.owner); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *sqliteStore) markEnrollmentCleanup(ctx context.Context, intent enrollmentIntent, leaseUntil int64) error {
	result, err := s.db.ExecContext(ctx, `UPDATE machine_enrollments SET phase='cleanup',lease_until=? WHERE machine_id=? AND lease_owner=?`, leaseUntil, intent.connection.ID, intent.owner)
	if err != nil {
		return err
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count != 1 {
		return failure(Unavailable, "Очистка подключения уже выполняется")
	}
	return nil
}
func (s *sqliteStore) releaseEnrollmentCleanup(ctx context.Context, intent enrollmentIntent) error {
	_, err := s.db.ExecContext(ctx, `UPDATE machine_enrollments SET phase='cleanup',lease_owner='',lease_until=0 WHERE machine_id=? AND lease_owner=?`, intent.connection.ID, intent.owner)
	return err
}
func (s *sqliteStore) finishEnrollmentCleanup(ctx context.Context, intent enrollmentIntent) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM machine_enrollments WHERE machine_id=? AND lease_owner=? AND phase='cleanup'`, intent.connection.ID, intent.owner)
	return err
}

// claimEnrollmentCleanup skips live operations; expired leases never activate.
func (s *sqliteStore) claimEnrollmentCleanup(ctx context.Context, owner string, now, leaseUntil int64, limit int) ([]enrollmentIntent, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	rows, err := tx.QueryContext(ctx, `SELECT machine_id,public_key,tunnel_address FROM machine_enrollments WHERE lease_until<=? ORDER BY last_attempt,machine_id LIMIT ?`, now, limit)
	if err != nil {
		return nil, err
	}
	var intents []enrollmentIntent
	for rows.Next() {
		var intent enrollmentIntent
		intent.owner = owner
		intent.phase = "cleanup"
		if err := rows.Scan(&intent.connection.ID, &intent.connection.PublicKey, &intent.connection.Address); err != nil {
			rows.Close()
			return nil, err
		}
		intents = append(intents, intent)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return nil, err
	}
	for _, intent := range intents {
		if _, err := tx.ExecContext(ctx, `UPDATE machine_enrollments SET phase='cleanup',lease_owner=?,lease_until=?,last_attempt=? WHERE machine_id=?`, owner, leaseUntil, now, intent.connection.ID); err != nil {
			return nil, err
		}
	}
	return intents, tx.Commit()
}
