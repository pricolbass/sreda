package cabinet

import (
	"bytes"
	"database/sql"
	"errors"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Rebuilding users also rebuilds its foreign-key dependent sessions. Copying
// them first preserves active v1 sessions without ALTER TABLE rename rewriting
// their foreign keys to a temporary table.
func migrateInvitations(tx *sql.Tx) error {
	_, err := tx.Exec(`
 CREATE TABLE users_new (id INTEGER PRIMARY KEY, login TEXT NOT NULL UNIQUE, password_hash BLOB NOT NULL, role TEXT NOT NULL CHECK(role IN ('admin','user')));
 INSERT INTO users_new SELECT id,login,password_hash,role FROM users;
 CREATE TEMP TABLE sessions_backup AS SELECT * FROM sessions;
 DROP TABLE sessions;
 DROP TABLE users;
 ALTER TABLE users_new RENAME TO users;
 CREATE TABLE sessions (token_hash BLOB PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
 INSERT INTO sessions SELECT * FROM sessions_backup;
 DROP TABLE sessions_backup;
 CREATE INDEX sessions_expiry ON sessions(expires_at);
 CREATE TABLE invitations (id INTEGER PRIMARY KEY, token_hash BLOB NOT NULL UNIQUE, created_by INTEGER NOT NULL REFERENCES users(id), expires_at INTEGER NOT NULL, cancelled_at INTEGER, used_at INTEGER);
 PRAGMA user_version=2;
 `)
	return err
}

type invitationView struct {
	ID              int64
	Expires, Status string
	CanCancel       bool
}
type pageData struct {
	CSRF, Login, Role, Error, InvitationLink, Token, Expires string
	Invitations                                              []invitationView
}

func (a *App) renderPage(w http.ResponseWriter, status int, page string, data pageData) {
	data.CSRF = randomToken()
	var body bytes.Buffer
	if err := a.pages.ExecuteTemplate(&body, page, data); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, csrfCookie, data.CSRF, int(sessionLifetime.Seconds()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}
func (a *App) registerInvitationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/invitations", a.invitationList)
	mux.HandleFunc("POST /admin/invitations", a.invitationCreate)
	mux.HandleFunc("POST /admin/invitations/{id}/cancel", a.invitationCancel)
	mux.HandleFunc("GET /invite/{token}", a.invitationPage)
	mux.HandleFunc("POST /invite/{token}", a.invitationAccept)
}
func (a *App) invitationList(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	a.showInvitations(w, r, http.StatusOK, "")
}
func (a *App) showInvitations(w http.ResponseWriter, r *http.Request, status int, link string) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,expires_at,cancelled_at,used_at FROM invitations ORDER BY id DESC`)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer rows.Close()
	data := pageData{InvitationLink: link}
	for rows.Next() {
		var item invitationView
		var expiry int64
		var cancelled, used sql.NullInt64
		if err := rows.Scan(&item.ID, &expiry, &cancelled, &used); err != nil {
			a.serverError(w, err)
			return
		}
		item.Expires = time.Unix(expiry, 0).UTC().Format("02.01.2006 15:04 UTC")
		switch {
		case used.Valid:
			item.Status = "Использовано"
		case cancelled.Valid:
			item.Status = "Отменено"
		case expiry <= time.Now().Unix():
			item.Status = "Срок истёк"
		default:
			item.Status = "Действует"
			item.CanCancel = true
		}
		data.Invitations = append(data.Invitations, item)
	}
	if err := rows.Err(); err != nil {
		a.serverError(w, err)
		return
	}
	a.renderPage(w, status, "invitations", data)
}
func (a *App) invitationCreate(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	durations := map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "168h": 7 * 24 * time.Hour}
	lifetime, ok := durations[r.PostForm.Get("lifetime")]
	if !ok {
		http.Error(w, "Выберите срок: 1 час, 24 часа или 7 дней", http.StatusBadRequest)
		return
	}
	token := randomToken()
	if _, err := a.db.ExecContext(r.Context(), `INSERT INTO invitations(token_hash,created_by,expires_at) VALUES(?,?,?)`, tokenHash(token), user.ID, time.Now().Add(lifetime).Unix()); err != nil {
		a.serverError(w, err)
		return
	}
	a.showInvitations(w, r, http.StatusCreated, a.origin+"/invite/"+token)
}
func (a *App) invitationCancel(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	result, err := a.db.ExecContext(r.Context(), `UPDATE invitations SET cancelled_at=? WHERE id=? AND used_at IS NULL AND cancelled_at IS NULL AND expires_at>?`, time.Now().Unix(), id, time.Now().Unix())
	if err != nil {
		a.serverError(w, err)
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		http.Error(w, "Приглашение уже недействительно", http.StatusConflict)
		return
	}
	http.Redirect(w, r, "/admin/invitations", http.StatusSeeOther)
}
func (a *App) invitationValid(r *http.Request) (int64, error) {
	var expiry int64
	err := a.db.QueryRowContext(r.Context(), `SELECT expires_at FROM invitations WHERE token_hash=? AND expires_at>? AND used_at IS NULL AND cancelled_at IS NULL`, tokenHash(r.PathValue("token")), time.Now().Unix()).Scan(&expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return expiry, err
}
func (a *App) invitationPage(w http.ResponseWriter, r *http.Request) {
	valid, err := a.invitationValid(r)
	if err != nil {
		a.serverError(w, err)
		return
	}
	if valid == 0 {
		http.Error(w, "Приглашение недействительно или срок истёк. Обратитесь к администратору.", http.StatusGone)
		return
	}
	a.renderPage(w, http.StatusOK, "invitation", pageData{Token: r.PathValue("token"), Expires: time.Unix(valid, 0).UTC().Format("02.01.2006 15:04 UTC")})
}
func (a *App) invitationAccept(w http.ResponseWriter, r *http.Request) {
	valid, err := a.invitationValid(r)
	if err != nil {
		a.serverError(w, err)
		return
	}
	if valid == 0 {
		http.Error(w, "Приглашение недействительно или срок истёк", http.StatusGone)
		return
	}
	login, password := r.PostForm.Get("login"), r.PostForm.Get("password")
	if !loginPattern.MatchString(login) || len(password) < 12 || len(password) > 72 {
		a.renderPage(w, http.StatusBadRequest, "invitation", pageData{Token: r.PathValue("token"), Error: "Логин: 3–64 латинских символа, цифры, _, . или -; первый символ — буква или цифра. Пароль: 12–72 байта."})
		return
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), passwordCost)
	if err != nil {
		a.serverError(w, err)
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer tx.Rollback()
	// The first write claims the invitation atomically across processes. Any
	// later failure rolls back the claim, so a login collision never consumes it.
	result, err := tx.ExecContext(r.Context(), `UPDATE invitations SET used_at=? WHERE token_hash=? AND expires_at>? AND used_at IS NULL AND cancelled_at IS NULL`, time.Now().Unix(), tokenHash(r.PathValue("token")), time.Now().Unix())
	if err != nil {
		a.serverError(w, err)
		return
	}
	count, _ := result.RowsAffected()
	if count == 0 {
		http.Error(w, "Приглашение недействительно или срок истёк", http.StatusGone)
		return
	}
	result, err = tx.ExecContext(r.Context(), `INSERT INTO users(login,password_hash,role) VALUES(?,?,'user') ON CONFLICT(login) DO NOTHING`, login, hash)
	if err != nil {
		a.serverError(w, err)
		return
	}
	count, _ = result.RowsAffected()
	if count == 0 {
		tx.Rollback()
		a.renderPage(w, http.StatusConflict, "invitation", pageData{Token: r.PathValue("token"), Error: "Этот логин уже занят. Выберите другой; приглашение остаётся действующим."})
		return
	}
	if err := tx.Commit(); err != nil {
		a.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
