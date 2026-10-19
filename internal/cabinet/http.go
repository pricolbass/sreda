package cabinet

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"log"
	"net/http"

	"sreda/internal/identity"
)

const sessionCookie = "__Host-sreda-session"
const csrfCookie = "__Host-sreda-csrf"
const sessionLifetime = identity.SessionLifetime

func (a *App) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", a.dashboard)
	mux.HandleFunc("GET /login", a.loginPage)
	mux.HandleFunc("POST /login", a.login)
	mux.HandleFunc("POST /logout", a.logout)
	a.registerPublicationRoutes(mux)
	a.registerMachineRoutes(mux)
	a.registerInvitationRoutes(mux)
	a.registerPasswordRecoveryRoutes(mux)
	return a.publications.Wrap(a.protect(mux))
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
	token, err := a.identity.SignIn(r.Context(), r.PostForm.Get("login"), r.PostForm.Get("password"), sessionToken(r))
	if errors.Is(err, identity.InvalidCredentials) {
		a.render(w, http.StatusUnauthorized, "login", "", err.Error())
		return
	}
	if err != nil {
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

// User remains an alias for machine and publication ownership adapters.
type User = identity.User

func sessionToken(r *http.Request) string {
	cookie, err := r.Cookie(sessionCookie)
	if err != nil {
		return ""
	}
	return cookie.Value
}
func (a *App) sessionUser(w http.ResponseWriter, r *http.Request, lookup func(context.Context, string) (User, error)) (User, bool) {
	user, err := lookup(r.Context(), sessionToken(r))
	if errors.Is(err, identity.Unauthenticated) {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return User{}, false
	}
	if errors.Is(err, identity.Forbidden) {
		http.Error(w, err.Error(), http.StatusForbidden)
		return User{}, false
	}
	if err != nil {
		a.serverError(w, err)
		return User{}, false
	}
	return user, true
}
func (a *App) currentUser(w http.ResponseWriter, r *http.Request) (User, bool) {
	return a.sessionUser(w, r, a.identity.CurrentUser)
}
func (a *App) requireAdmin(w http.ResponseWriter, r *http.Request) (User, bool) {
	return a.sessionUser(w, r, a.identity.Administrator)
}

func (a *App) logout(w http.ResponseWriter, r *http.Request) {
	if err := a.identity.SignOut(r.Context(), sessionToken(r)); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, sessionCookie, "", -1)
	setCookie(w, csrfCookie, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func (a *App) serverError(w http.ResponseWriter, err error) {
	log.Printf("cabinet: %v", err)
	http.Error(w, "Внутренняя ошибка. Повторите позже.", http.StatusInternalServerError)
}
