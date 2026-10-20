package machine

import (
	"context"
	"database/sql"
	"errors"
	"time"
)

func (s *sqliteStore) prepareReconnect(ctx context.Context, actor Actor, id, revision int64, owner string, now time.Time) (Reconnection, error) {
	r := Reconnection{owner: owner}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return r, err
	}
	defer tx.Rollback()
	var ownerID int64
	var blocked, deleting bool
	err = tx.QueryRowContext(ctx, `SELECT m.id,m.owner_id,m.access_revision,m.mode,COALESCE(m.public_key,''),COALESCE(m.tunnel_address,''),u.access_revision,u.blocked,EXISTS(SELECT 1 FROM machine_deletions d WHERE d.machine_id=m.id) FROM machines m JOIN users u ON u.id=m.owner_id WHERE m.id=?`, id).Scan(&r.connection.ID, &ownerID, &r.connection.Revision, &r.connection.Mode, &r.connection.PublicKey, &r.connection.Address, &r.connection.OwnerRevision, &blocked, &deleting)
	if errors.Is(err, sql.ErrNoRows) || ownerID != actor.ID {
		return r, failure(NotFound, "Машина не найдена")
	}
	if err != nil {
		return r, err
	}
	r.connection.OwnerID = ownerID
	if blocked {
		return r, failure(Unauthorized, "Доступ пользователя закрыт")
	}
	if deleting {
		return r, failure(Conflict, "Машина уже удаляется")
	}
	var source, ownerRevision, until int64
	err = tx.QueryRowContext(ctx, `SELECT source_revision,owner_revision,lease_until FROM machine_reconnections WHERE machine_id=?`, id).Scan(&source, &ownerRevision, &until)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return r, err
	}

	fresh := errors.Is(err, sql.ErrNoRows)
	if !fresh {
		if until > now.Unix() {
			return r, failure(Unavailable, "Переподключение ещё выполняется")
		}
		if ownerRevision != r.connection.OwnerRevision || r.connection.Revision != source+1 {
			if revision != r.connection.Revision {
				return r, failure(Conflict, "Права или подключение изменились; обновите страницу")
			}
			fresh = true
		} else if revision != source && revision != r.connection.Revision {
			return r, failure(Conflict, "Подключение изменилось; обновите страницу")
		}
	}
	if fresh {
		if revision != r.connection.Revision {
			return r, failure(Conflict, "Подключение изменилось; обновите страницу")
		}
		source = revision
		r.connection.Revision++
		if _, err = tx.ExecContext(ctx, `UPDATE machines SET enabled=0,credential_hash=NULL,code_hash=NULL,code_expires_at=NULL,last_seen=NULL,access_revision=?,access_state='Переподключение',access_error='' WHERE id=?`, r.connection.Revision, id); err != nil {
			return r, err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO machine_reconnections(machine_id,source_revision,owner_revision,lease_owner,lease_until)VALUES(?,?,?,?,?) ON CONFLICT(machine_id)DO UPDATE SET lease_owner=excluded.lease_owner,lease_until=excluded.lease_until,source_revision=excluded.source_revision,owner_revision=excluded.owner_revision,error=''`, id, source, r.connection.OwnerRevision, owner, now.Add(enrollmentLease).Unix()); err != nil {
		return r, err
	}
	return r, tx.Commit()
}
func (s *sqliteStore) reconnectReady(ctx context.Context, r Reconnection) error {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM machine_reconnections x JOIN machines m ON m.id=x.machine_id JOIN users u ON u.id=m.owner_id WHERE x.machine_id=? AND x.lease_owner=? AND x.lease_until>? AND m.access_revision=? AND u.blocked=0 AND u.access_revision=? AND NOT EXISTS(SELECT 1 FROM machine_deletions d WHERE d.machine_id=m.id) AND NOT EXISTS(SELECT 1 FROM machine_enrollments e WHERE e.machine_id=m.id) AND NOT EXISTS(SELECT 1 FROM machine_connection_ops o WHERE o.machine_id=m.id)`, r.connection.ID, r.owner, time.Now().Unix(), r.connection.Revision, r.connection.OwnerRevision).Scan(&n)
	if err == nil && n != 1 {
		return failure(Unavailable, "Предыдущая настройка ещё выполняется или ожидает очистки; повторите позже")
	}
	return err
}
func (s *sqliteStore) releaseReconnect(ctx context.Context, r Reconnection, message string) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `UPDATE machine_reconnections SET lease_owner='',lease_until=0,error=? WHERE machine_id=? AND lease_owner=?`, message, r.connection.ID, r.owner); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE machines SET access_state='Ошибка переподключения',access_error=? WHERE id=? AND access_revision=?`, message, r.connection.ID, r.connection.Revision); err != nil {
		return err
	}
	return tx.Commit()
}
func (s *sqliteStore) finishReconnect(ctx context.Context, r Reconnection, e Enrollment) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE machines SET credential_hash=NULL,public_key=NULL,proxy_token=NULL,code_hash=?,code_expires_at=?,access_state='Ожидает переподключения',access_error='' WHERE id=? AND enabled=0 AND access_revision=? AND EXISTS(SELECT 1 FROM users u WHERE u.id=machines.owner_id AND u.blocked=0 AND u.access_revision=?) AND EXISTS(SELECT 1 FROM machine_reconnections x WHERE x.machine_id=machines.id AND x.lease_owner=? AND x.lease_until>?) AND NOT EXISTS(SELECT 1 FROM machine_enrollments e WHERE e.machine_id=machines.id) AND NOT EXISTS(SELECT 1 FROM machine_connection_ops o WHERE o.machine_id=machines.id) AND NOT EXISTS(SELECT 1 FROM machine_deletions d WHERE d.machine_id=machines.id)`, hash(e.Code), e.ExpiresAt.Unix(), r.connection.ID, r.connection.Revision, r.connection.OwnerRevision, r.owner, time.Now().Unix())
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return failure(Unavailable, "Переподключение изменилось; новый код не выдан")
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM machine_reconnections WHERE machine_id=? AND lease_owner=?`, r.connection.ID, r.owner); err != nil {
		return err
	}
	return tx.Commit()
}

func (s *sqliteStore) claimReconnectPending(ctx context.Context, r Reconnection, now time.Time) (*enrollmentIntent, *connectionOperation, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback()
	var found int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM machine_reconnections x JOIN machines m ON m.id=x.machine_id JOIN users u ON u.id=m.owner_id WHERE x.machine_id=? AND x.lease_owner=? AND x.lease_until>? AND m.access_revision=? AND u.blocked=0 AND u.access_revision=?`, r.connection.ID, r.owner, now.Unix(), r.connection.Revision, r.connection.OwnerRevision).Scan(&found); err != nil {
		return nil, nil, err
	}
	if found != 1 {
		return nil, nil, failure(Unavailable, "Переподключение изменилось")
	}
	var enrollment *enrollmentIntent
	var operation *connectionOperation
	var e enrollmentIntent
	var until int64
	err = tx.QueryRowContext(ctx, `SELECT public_key,tunnel_address,lease_until FROM machine_enrollments WHERE machine_id=?`, r.connection.ID).Scan(&e.connection.PublicKey, &e.connection.Address, &until)
	if err == nil {
		if until > now.Unix() {
			return nil, nil, failure(Unavailable, "Прежнее подключение ещё выполняется; дождитесь его очистки")
		}
		e.connection.ID = r.connection.ID
		e.owner = r.owner
		e.phase = "cleanup"
		enrollment = &e
		if _, err = tx.ExecContext(ctx, `UPDATE machine_enrollments SET phase='cleanup',lease_owner=?,lease_until=?,last_attempt=? WHERE machine_id=?`, r.owner, now.Add(enrollmentLease).Unix(), now.Unix(), r.connection.ID); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}
	err = tx.QueryRowContext(ctx, `SELECT lease_until FROM machine_connection_ops WHERE machine_id=?`, r.connection.ID).Scan(&until)
	if err == nil {
		if until > now.Unix() {
			return nil, nil, failure(Unavailable, "Прежнее изменение подключения ещё выполняется; дождитесь его очистки")
		}
		o := connectionOperation{connection: r.connection, owner: r.owner}
		operation = &o
		if _, err = tx.ExecContext(ctx, `UPDATE machine_connection_ops SET desired_enabled=0,phase='cleanup',lease_owner=?,lease_until=?,last_attempt=? WHERE machine_id=?`, r.owner, now.Add(enrollmentLease).Unix(), now.Unix(), r.connection.ID); err != nil {
			return nil, nil, err
		}
	} else if !errors.Is(err, sql.ErrNoRows) {
		return nil, nil, err
	}
	return enrollment, operation, tx.Commit()
}

func InstallReconnectionSchema(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE IF NOT EXISTS machine_reconnections(machine_id INTEGER PRIMARY KEY REFERENCES machines(id) ON DELETE CASCADE,source_revision INTEGER NOT NULL,owner_revision INTEGER NOT NULL,lease_owner TEXT NOT NULL,lease_until INTEGER NOT NULL,error TEXT NOT NULL DEFAULT '');`)
	return err
}
