package cabinet

import (
	"bytes"
	"errors"
	"net/http"
	"sreda/internal/identity"
	"strconv"
)

type accessData struct {
	CSRF  string
	Users []identity.AccountAccess
}

func (a *App) registerAccessRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /admin/users", a.accessUsers)
	mux.HandleFunc("POST /admin/users/{id}/block", a.blockUser)
	mux.HandleFunc("POST /admin/users/{id}/unblock", a.unblockUser)
}
func (a *App) accessUsers(w http.ResponseWriter, r *http.Request) {
	actor, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	users, err := a.identity.AccountAccess(r.Context(), actor.ID)
	if err != nil {
		a.identityError(w, err)
		return
	}
	data := accessData{randomToken(), users}
	var body bytes.Buffer
	if err := a.pages.ExecuteTemplate(&body, "access-users", data); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, csrfCookie, data.CSRF, int(sessionLifetime.Seconds()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body.Bytes())
}
func (a *App) blockUser(w http.ResponseWriter, r *http.Request)   { a.changeUserAccess(w, r, true) }
func (a *App) unblockUser(w http.ResponseWriter, r *http.Request) { a.changeUserAccess(w, r, false) }
func (a *App) changeUserAccess(w http.ResponseWriter, r *http.Request, block bool) {
	actor, ok := a.requireAdmin(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	revision, revErr := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if err != nil || revErr != nil {
		http.Error(w, "Некорректная команда", 400)
		return
	}
	if block {
		err = a.access.Block(r.Context(), actor.ID, id, revision)
	} else {
		err = a.access.Unblock(r.Context(), actor.ID, id, revision)
	}
	if err != nil {
		switch {
		case errors.Is(err, identity.AccessConflict), errors.Is(err, identity.AccessIncomplete):
			http.Error(w, err.Error(), 409)
		case errors.Is(err, identity.UserNotFound):
			http.Error(w, err.Error(), 404)
		case errors.Is(err, identity.Forbidden):
			http.Error(w, err.Error(), 403)
		default:
			http.Error(w, "Закрытие доступа не подтверждено; повторите действие. "+err.Error(), 503)
		}
		return
	}
	http.Redirect(w, r, "/admin/users", 303)
}

const accessTemplates = `{{define "access-users"}}{{template "head"}}<body><header><a href="/">Среда</a><span>Администратор</span></header><main><h1>Доступ пользователей</h1><p>Блокировка отзывает сессии и закрывает публикации и подключения. Разблокировка разрешает новый вход; ресурсы включаются отдельно.</p>{{range .Users}}<section class="card"><h2>{{.Login}}</h2><p>{{.State}}</p>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}<form method="post" action="/admin/users/{{.ID}}/{{if .Blocked}}block{{else}}block{{end}}"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="revision" value="{{.Revision}}"><button>{{if .Blocked}}Повторить закрытие доступа{{else}}Заблокировать{{end}}</button></form>{{if .Blocked}}<form method="post" action="/admin/users/{{.ID}}/unblock"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="revision" value="{{.Revision}}"><button>Разблокировать</button></form>{{end}}</section>{{end}}</main></body></html>{{end}}`
