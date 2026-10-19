// Package cabinet owns accounts, invitations, and server-side sessions.
package cabinet

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"html/template"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sreda/internal/agentcontrol"
	"sreda/internal/machine"
	"sreda/internal/publication"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

const passwordCost = 12

var loginPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$`)

type App struct {
	db           *sql.DB
	origin       string
	host         string
	pages        *template.Template
	machines     *machine.Manager
	agentControl *agentcontrol.Controller
	publications *publication.Module
}

// Open creates the state directory and schema on first use. The origin is saved
// with the database; later invocations may omit it, but cannot silently change it.
func Open(dataDir, origin string) (*App, error) {
	if dataDir == "" {
		return nil, errors.New("укажите --data-dir")
	}
	if err := os.MkdirAll(dataDir, 0700); err != nil {
		return nil, err
	}
	path, err := filepath.Abs(filepath.Join(dataDir, "sreda.sqlite3"))
	if err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err := file.Close(); err != nil {
		return nil, err
	}
	dsn := url.URL{Scheme: "file", Path: path}
	q := dsn.Query()
	q.Add("_pragma", "foreign_keys(1)")
	q.Add("_txlock", "immediate")
	q.Add("_pragma", "busy_timeout(5000)")
	q.Add("_pragma", "journal_mode(WAL)")
	dsn.RawQuery = q.Encode()
	db, err := sql.Open("sqlite", dsn.String())
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	app := &App{db: db}
	if err := app.initialize(origin); err != nil {
		db.Close()
		return nil, err
	}
	app.publications, err = publication.New(db, app.host, publication.AgentTransport{})
	if err != nil {
		db.Close()
		return nil, err
	}
	app.machines = machine.New(db)
	app.agentControl = agentcontrol.New(app.machines, app.publications)
	app.pages, err = template.New("pages").Parse(pageTemplates + invitationTemplates + recoveryTemplates)
	if err != nil {
		db.Close()
		return nil, err
	}
	return app, nil
}

func (a *App) initialize(origin string) error {
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var version int
	if err := tx.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	if version > 3 {
		return errors.New("версия базы новее приложения")
	}
	if version == 0 {
		_, err = tx.Exec(`
			CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
			CREATE TABLE users (
				id INTEGER PRIMARY KEY,
				login TEXT NOT NULL UNIQUE,
				password_hash BLOB NOT NULL,
				role TEXT NOT NULL CHECK (role = 'admin')
			);
			CREATE TABLE sessions (
				token_hash BLOB PRIMARY KEY,
				user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
				expires_at INTEGER NOT NULL
			);
			CREATE INDEX sessions_expiry ON sessions(expires_at);
			PRAGMA user_version = 1;
		`)
		if err != nil {
			return err
		}
	}
	if version < 2 {
		if err := migrateInvitations(tx); err != nil {
			return err
		}
	}
	if version < 3 {
		if err := installPasswordRecovery(tx); err != nil {
			return err
		}
	}
	if err := installMachineSchema(tx); err != nil {
		return err
	}

	if err := publication.InstallSchema(tx); err != nil {
		return err
	}
	var saved string
	err = tx.QueryRow("SELECT value FROM settings WHERE key = 'origin'").Scan(&saved)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	origin = strings.TrimSuffix(origin, "/")
	if saved != "" {
		if origin != "" && origin != saved {
			return errors.New("origin отличается от сохранённого адреса кабинета")
		}
		origin = saved
	}
	u, err := url.Parse(origin)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return errors.New("при первом запуске задайте --origin в виде https://cabinet.example.com")
	}
	if _, err := tx.Exec("INSERT OR IGNORE INTO settings (key, value) VALUES ('origin', ?)", origin); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	a.origin, a.host = origin, u.Host
	return nil
}

func (a *App) Close() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if a.publications != nil {
		_ = a.publications.Close(ctx)
	}
	return a.db.Close()
}

// CreateAdministrator is available only to the local CLI, never over HTTP.
func (a *App) CreateAdministrator(login, password string) error {
	if !loginPattern.MatchString(login) {
		return errors.New("логин: 3–64 символа, латинские буквы, цифры, _, . или -; первый символ — буква или цифра")
	}
	hash, err := accountPasswordHash(password)
	if err != nil {
		return err
	}
	result, err := a.db.Exec("INSERT INTO users (login, password_hash, role) VALUES (?, ?, 'admin') ON CONFLICT(login) DO NOTHING", login, hash)
	if err != nil {
		return fmt.Errorf("создание администратора: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("логин уже занят; существующая учётная запись не изменена")
	}
	return nil
}

func tokenHash(token string) []byte {
	hash := sha256.Sum256([]byte(token))
	return hash[:]
}
