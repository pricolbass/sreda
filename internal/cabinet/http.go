package cabinet

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"errors"
	"log"
	"net/http"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const sessionCookie = "__Host-sreda-session"
const csrfCookie = "__Host-sreda-csrf"
const sessionLifetime = 12 * time.Hour

var dummyPasswordHash = sync.OnceValue(func() []byte {
	hash, err := bcrypt.GenerateFromPassword([]byte("unused-account-password"), passwordCost)
	if err != nil {
		panic(err)
	}
	return hash
})

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.dashboard)
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /logout", a.logout)
	a.registerMachineRoutes(mux)
	a.registerInvitationRoutes(mux)
	a.registerPasswordRecoveryRoutes(mux)
	return a.protect(mux)
}

func (a *App) protect(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "same-origin")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		if r.Host != a.host {
			http.Error(w, "Неизвестный адрес кабинета", http.StatusBadRequest)
			return
		}
		// Production requests arrive exclusively through a private Unix socket.
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Error(w, "Требуется HTTPS", http.StatusForbidden)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.Method != "GET" && r.Method != "HEAD" {
			r.Body = http.MaxBytesReader(w, r.Body, 4096)
			if r.URL.Path == "/api/agent/enroll" || r.URL.Path == "/api/agent/heartbeat" {
				next.ServeHTTP(w, r)
				return
			}
			if err := r.ParseForm(); err != nil {
				http.Error(w, "Некорректная форма", http.StatusBadRequest)
				return
			}
			cookie, err := r.Cookie(csrfCookie)
			token := r.PostForm.Get("csrf")
			if r.Header.Get("Origin") != a.origin || err != nil || len(token) != 43 || subtle.ConstantTimeCompare([]byte(cookie.Value), []byte(token)) != 1 {
				http.Error(w, "Обновите страницу и повторите действие", http.StatusForbidden)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func randomToken() string {
	var raw [32]byte
	_, _ = rand.Read(raw[:]) // crypto/rand.Read terminates the process on failure.
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	http.SetCookie(w, &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge,
		Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
}

func (a *App) render(w http.ResponseWriter, status int, page, login, message string) {
	token := randomToken()
	var body bytes.Buffer
	data := pageData{CSRF: token, Login: login, Error: message, Role: "admin"}
	if err := a.pages.ExecuteTemplate(&body, page, data); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, csrfCookie, token, int(sessionLifetime.Seconds()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body.Bytes())
}

func (a *App) loginPage(w http.ResponseWriter, r *http.Request) {
	a.render(w, http.StatusOK, "login", "", "")
}

func (a *App) login(w http.ResponseWriter, r *http.Request) {
	var id int64
	var hash []byte
	err := a.db.QueryRowContext(r.Context(), "SELECT id, password_hash FROM users WHERE login = ?", r.PostForm.Get("login")).Scan(&id, &hash)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		a.serverError(w, err)
		return
	}
	if errors.Is(err, sql.ErrNoRows) {
		hash = dummyPasswordHash()
	}
	password := r.PostForm.Get("password")
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || id == 0 || len(password) > 72 {
		a.render(w, http.StatusUnauthorized, "login", "", "Неверный логин или пароль")
		return
	}
	token := randomToken()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE expires_at <= ?", time.Now().Unix()); err != nil {
		a.serverError(w, err)
		return
	}
	if old, err := r.Cookie(sessionCookie); err == nil {
		if _, err := tx.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash = ?", tokenHash(old.Value)); err != nil {
			a.serverError(w, err)
			return
		}
	}
	result, err := tx.ExecContext(r.Context(), "INSERT INTO sessions (token_hash, user_id, expires_at) SELECT ?, id, ? FROM users WHERE id = ? AND password_hash = ?", tokenHash(token), time.Now().Add(sessionLifetime).Unix(), id, hash)
	if err != nil {
		a.serverError(w, err)
		return
	}
	count, _ := result.RowsAffected()
	if count != 1 {
		tx.Rollback()
		a.render(w, http.StatusUnauthorized, "login", "", "Неверный логин или пароль")
		return
	}
	if err := tx.Commit(); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, sessionCookie, token, int(sessionLifetime.Seconds()))
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *App) dashboard(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	a.renderPage(w, http.StatusOK, "dashboard", pageData{Login: user.Login, Role: user.Role})
}

// User identifies the account authorized by the current server-side session.
type User struct {
	ID          int64
	Login, Role string
}

func (a *App) currentUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	var user User
	cookie, err := r.Cookie(sessionCookie)
	if err == nil {
		err = a.db.QueryRowContext(r.Context(), `SELECT users.id, users.login, users.role FROM sessions JOIN users ON users.id = sessions.user_id
   WHERE sessions.token_hash = ? AND sessions.expires_at > ?`, tokenHash(cookie.Value), time.Now().Unix()).Scan(&user.ID, &user.Login, &user.Role)
	}
	if errors.Is(err, http.ErrNoCookie) || errors.Is(err, sql.ErrNoRows) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return User{}, false
	}
	if err != nil {
		a.serverError(w, err)
		return User{}, false
	}
	return user, true
}

func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) (User, bool) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return User{}, false
	}
	if user.Role != "admin" {
		http.Error(w, "Требуются права администратора", http.StatusForbidden)
		return User{}, false
	}
	return user, true
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(sessionCookie); err == nil {
		if _, err := a.db.ExecContext(r.Context(), "DELETE FROM sessions WHERE token_hash = ?", tokenHash(cookie.Value)); err != nil {
			a.serverError(w, err)
			return
		}
	}
	setCookie(w, sessionCookie, "", -1)
	setCookie(w, csrfCookie, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) serverError(w http.ResponseWriter, err error) {
	log.Printf("cabinet: %v", err)
	http.Error(w, "Внутренняя ошибка. Повторите позже.", http.StatusInternalServerError)
}
