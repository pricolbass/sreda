package cabinet

import (
	"bytes"
	"errors"
	"net/http"
	"strconv"
	"time"

	"sreda/internal/identity"
)

type invitationView struct {
	ID              int64
	Expires, Status string
	CanCancel       bool
}
type pageData struct {
	CSRF, Login, Role, Error, InvitationLink, Token, Expires string
	Invitations                                              []invitationView
}

func displayExpiry(expiry time.Time) string { return expiry.UTC().Format("02.01.2006 15:04 UTC") }
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
	user, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	a.showInvitations(w, r, user.ID, http.StatusOK, "")
}
func (a *App) showInvitations(w http.ResponseWriter, r *http.Request, actorID int64, status int, link string) {
	invitations, err := a.identity.Invitations(r.Context(), actorID)
	if err != nil {
		a.identityError(w, err)
		return
	}
	data := pageData{InvitationLink: link}
	labels := map[identity.InvitationState]string{identity.InvitationUsed: "Использовано", identity.InvitationCancelled: "Отменено", identity.InvitationExpired: "Срок истёк", identity.InvitationActive: "Действует"}
	for _, invitation := range invitations {
		data.Invitations = append(data.Invitations, invitationView{ID: invitation.ID, Expires: displayExpiry(invitation.ExpiresAt), Status: labels[invitation.State], CanCancel: invitation.State == identity.InvitationActive})
	}
	a.renderPage(w, status, "invitations", data)
}
func (a *App) invitationCreate(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	link, err := a.identity.IssueInvitation(r.Context(), user.ID, r.PostForm.Get("lifetime"))
	if err != nil {
		a.identityError(w, err)
		return
	}
	a.showInvitations(w, r, user.ID, http.StatusCreated, a.origin+"/invite/"+link.Token)
}
func (a *App) invitationCancel(w http.ResponseWriter, r *http.Request) {
	user, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	if err := a.identity.CancelInvitation(r.Context(), user.ID, id); err != nil {
		a.identityError(w, err)
		return
	}
	http.Redirect(w, r, "/admin/invitations", http.StatusSeeOther)
}
func (a *App) invitationPage(w http.ResponseWriter, r *http.Request) {
	expiry, err := a.identity.Invitation(r.Context(), r.PathValue("token"))
	if errors.Is(err, identity.InvitationInactive) {
		http.Error(w, "Приглашение недействительно или срок истёк. Обратитесь к администратору.", http.StatusGone)
		return
	}
	if err != nil {
		a.identityError(w, err)
		return
	}
	a.renderPage(w, http.StatusOK, "invitation", pageData{Token: r.PathValue("token"), Expires: displayExpiry(expiry)})
}
func (a *App) invitationAccept(w http.ResponseWriter, r *http.Request) {
	err := a.identity.AcceptInvitation(r.Context(), r.PathValue("token"), r.PostForm.Get("login"), r.PostForm.Get("password"))
	if errors.Is(err, identity.InvalidAccount) {
		a.renderPage(w, http.StatusBadRequest, "invitation", pageData{Token: r.PathValue("token"), Error: err.Error()})
		return
	}
	if errors.Is(err, identity.LoginTaken) {
		a.renderPage(w, http.StatusConflict, "invitation", pageData{Token: r.PathValue("token"), Error: err.Error()})
		return
	}
	if err != nil {
		a.identityError(w, err)
		return
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

// identityError translates application outcomes, without inspecting account state.
func (a *App) identityError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, identity.Forbidden):
		http.Error(w, err.Error(), http.StatusForbidden)
	case errors.Is(err, identity.InvalidLifetime):
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, identity.InvitationInactive), errors.Is(err, identity.RecoveryInactive):
		http.Error(w, err.Error(), http.StatusGone)
	case errors.Is(err, identity.InvitationConflict):
		http.Error(w, err.Error(), http.StatusConflict)
	case errors.Is(err, identity.UserNotFound):
		http.Error(w, err.Error(), http.StatusNotFound)
	default:
		a.serverError(w, err)
	}
}
