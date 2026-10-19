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

const recoveryLifetime = time.Hour

// All account creation and recovery paths enforce bcrypt's 72-byte boundary.
func validateAccountPassword(password string) error {
	if len(password) < 12 || len(password) > 72 {
		return errors.New("пароль должен содержать от 12 до 72 байт")
	}
	return nil
}
func accountPasswordHash(password string) ([]byte, error) {
	if err := validateAccountPassword(password); err != nil {
		return nil, err
	}
	return bcrypt.GenerateFromPassword([]byte(password), passwordCost)
}
func installPasswordRecovery(tx *sql.Tx) error {
	_, err := tx.Exec(`CREATE TABLE password_recovery(user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,token_hash BLOB NOT NULL UNIQUE,expires_at INTEGER NOT NULL,used_at INTEGER); PRAGMA user_version=3;`)
	return err
}

type recoveryUser struct {
	ID    int64
	Login string
}
type recoveryData struct {
	CSRF, Error, Link, Token, Expires string
	Users                             []recoveryUser
}

func (a *App) renderRecovery(w http.ResponseWriter, status int, page string, data recoveryData) {
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
func (a *App) registerPasswordRecoveryRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/password-recovery", a.recoveryAdmin)
	mux.HandleFunc("POST /admin/password-recovery", a.recoveryIssue)
	mux.HandleFunc("GET /recover/{token}", a.recoveryPage)
	mux.HandleFunc("POST /recover/{token}", a.recoveryApply)
}
func (a *App) recoveryAdmin(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	a.showRecoveryAdmin(w, r, http.StatusOK, recoveryData{})
}
func (a *App) showRecoveryAdmin(w http.ResponseWriter, r *http.Request, status int, data recoveryData) {
	rows, err := a.db.QueryContext(r.Context(), `SELECT id,login FROM users WHERE role='user' ORDER BY login`)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer rows.Close()
	for rows.Next() {
		var user recoveryUser
		if err := rows.Scan(&user.ID, &user.Login); err != nil {
			a.serverError(w, err)
			return
		}
		data.Users = append(data.Users, user)
	}
	if err := rows.Err(); err != nil {
		a.serverError(w, err)
		return
	}
	a.renderRecovery(w, status, "recovery-admin", data)
}
func (a *App) recoveryIssue(w http.ResponseWriter, r *http.Request) {
	if _, ok := a.requireAdmin(w, r); !ok {
		return
	}
	id, err := strconv.ParseInt(r.PostForm.Get("user_id"), 10, 64)
	if err != nil {
		http.Error(w, "Выберите пользователя", http.StatusBadRequest)
		return
	}
	token := randomToken()
	expiry := time.Now().Add(recoveryLifetime)
	result, err := a.db.ExecContext(r.Context(), `INSERT INTO password_recovery(user_id,token_hash,expires_at) SELECT id,?,? FROM users WHERE id=? AND role='user' ON CONFLICT(user_id) DO UPDATE SET token_hash=excluded.token_hash,expires_at=excluded.expires_at,used_at=NULL`, tokenHash(token), expiry.Unix(), id)
	if err != nil {
		a.serverError(w, err)
		return
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		http.Error(w, "Обычный пользователь не найден", http.StatusNotFound)
		return
	}
	a.showRecoveryAdmin(w, r, http.StatusCreated, recoveryData{Link: a.origin + "/recover/" + token, Expires: expiry.UTC().Format("02.01.2006 15:04 UTC")})
}
func (a *App) validRecovery(r *http.Request) (int64, error) {
	var expiry int64
	err := a.db.QueryRowContext(r.Context(), `SELECT expires_at FROM password_recovery JOIN users ON users.id=password_recovery.user_id WHERE token_hash=? AND expires_at>? AND used_at IS NULL AND role='user'`, tokenHash(r.PathValue("token")), time.Now().Unix()).Scan(&expiry)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, nil
	}
	return expiry, err
}
func (a *App) recoveryPage(w http.ResponseWriter, r *http.Request) {
	expiry, err := a.validRecovery(r)
	if err != nil {
		a.serverError(w, err)
		return
	}
	if expiry == 0 {
		http.Error(w, "Ссылка восстановления недействительна или срок истёк", http.StatusGone)
		return
	}
	a.renderRecovery(w, http.StatusOK, "recovery", recoveryData{Token: r.PathValue("token"), Expires: time.Unix(expiry, 0).UTC().Format("02.01.2006 15:04 UTC")})
}
func (a *App) recoveryApply(w http.ResponseWriter, r *http.Request) {
	expiry, err := a.validRecovery(r)
	if err != nil {
		a.serverError(w, err)
		return
	}
	if expiry == 0 {
		http.Error(w, "Ссылка восстановления недействительна или срок истёк", http.StatusGone)
		return
	}
	hash, err := accountPasswordHash(r.PostForm.Get("password"))
	if err != nil {
		a.renderRecovery(w, http.StatusBadRequest, "recovery", recoveryData{Token: r.PathValue("token"), Expires: time.Unix(expiry, 0).UTC().Format("02.01.2006 15:04 UTC"), Error: err.Error()})
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer tx.Rollback()
	// Atomically claim the link before changing the account. A replacement link
	// or another application instance can win, but only one change commits.
	var userID int64
	err = tx.QueryRowContext(r.Context(), `UPDATE password_recovery SET used_at=? WHERE token_hash=? AND expires_at>? AND used_at IS NULL AND user_id IN (SELECT id FROM users WHERE role='user') RETURNING user_id`, time.Now().Unix(), tokenHash(r.PathValue("token")), time.Now().Unix()).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Ссылка восстановления недействительна или срок истёк", http.StatusGone)
		return
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `UPDATE users SET password_hash=? WHERE id=? AND role='user'`, hash, userID); err != nil {
		a.serverError(w, err)
		return
	}
	if _, err := tx.ExecContext(r.Context(), `DELETE FROM sessions WHERE user_id=?`, userID); err != nil {
		a.serverError(w, err)
		return
	}
	if err := tx.Commit(); err != nil {
		a.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// ResetAdministratorPassword is an operator-only local CLI recovery path.
// It cannot change ordinary accounts or create an administrator.
func (a *App) ResetAdministratorPassword(login, password string) error {
	hash, err := accountPasswordHash(password)
	if err != nil {
		return err
	}
	tx, err := a.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.Exec(`UPDATE users SET password_hash=? WHERE login=? AND role='admin'`, hash, login)
	if err != nil {
		return err
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		return errors.New("администратор не найден")
	}
	if _, err := tx.Exec(`DELETE FROM sessions WHERE user_id IN (SELECT id FROM users WHERE login=? AND role='admin')`, login); err != nil {
		return err
	}
	return tx.Commit()
}
