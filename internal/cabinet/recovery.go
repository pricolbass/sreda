package cabinet

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"

	"sreda/internal/identity"
)

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
	user, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.showRecoveryAdmin(w, r, user.ID, http.StatusOK, recoveryData{})
}
func (a *App) showRecoveryAdmin(w http.ResponseWriter, r *http.Request, actorID int64, status int, data recoveryData) {
	users, err := a.identity.RecoveryUsers(r.Context(), actorID)
	if err != nil {
		a.identityError(w, err)
		return
	}
	for _, user := range users {
		data.Users = append(data.Users, recoveryUser{ID: user.ID, Login: user.Login})
	}
	a.renderRecovery(w, status, "recovery-admin", data)
}
func (a *App) recoveryIssue(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PostForm.Get("user_id"), 10, 64)
	if err != nil {
		http.Error(w, "Выберите пользователя", http.StatusBadRequest)
		return
	}
	link, err := a.identity.IssueRecovery(r.Context(), user.ID, id)
	if err != nil {
		a.identityError(w, err)
		return
	}
	a.showRecoveryAdmin(w, r, user.ID, http.StatusCreated, recoveryData{Link: a.origin + "/recover/" + link.Token, Expires: displayExpiry(link.ExpiresAt)})
}
func (a *App) recoveryPage(w http.ResponseWriter, r *http.Request) {
	expiry, err := a.identity.Recovery(r.Context(), r.PathValue("token"))
	if err != nil {
		a.identityError(w, err)
		return
	}
	a.renderRecovery(w, http.StatusOK, "recovery", recoveryData{Token: r.PathValue("token"), Expires: displayExpiry(expiry)})
}
func (a *App) recoveryApply(w http.ResponseWriter, r *http.Request) {
	expiry, err := a.identity.RecoverPassword(r.Context(), r.PathValue("token"), r.PostForm.Get("password"))
	if errors.Is(err, identity.InvalidPassword) {
		a.renderRecovery(w, http.StatusBadRequest, "recovery", recoveryData{Token: r.PathValue("token"), Expires: displayExpiry(expiry), Error: err.Error()})
		return
	}
	if err != nil {
		a.identityError(w, err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
