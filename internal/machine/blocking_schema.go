package machine

import "database/sql"

func InstallAccessSchema(tx *sql.Tx) error {
	rows, err := tx.Query("PRAGMA table_info(machines)")
	if err != nil {
		return err
	}
	found := false
	for rows.Next() {
		var cid, nn, pk int
		var name, kind string
		var d any
		if err := rows.Scan(&cid, &name, &kind, &nn, &d, &pk); err != nil {
			rows.Close()
			return err
		}
		if name == "desired_enabled" {
			found = true
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return err
	}
	if found {
		return nil
	}
	_, err = tx.Exec(`ALTER TABLE machines ADD COLUMN desired_enabled INTEGER NOT NULL DEFAULT 0; UPDATE machines SET desired_enabled=enabled; ALTER TABLE machines ADD COLUMN access_revision INTEGER NOT NULL DEFAULT 1; ALTER TABLE machines ADD COLUMN access_state TEXT NOT NULL DEFAULT 'Отключено'; UPDATE machines SET access_state='Подключено' WHERE enabled=1; ALTER TABLE machines ADD COLUMN access_error TEXT NOT NULL DEFAULT '';`)
	return err
}
