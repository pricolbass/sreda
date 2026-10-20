package cabinet

import (
	"bytes"
	"context"
	"errors"
	"html/template"
	"net"
	"net/http"
	"sreda/internal/publication"
	"strconv"
	"strings"
)

func (a *App) ConfigurePublicationZone(zone string) error {
	return a.publications.ConfigureZone(context.Background(), zone)
}
func (a *App) SetPublicationDialer(dial func(context.Context, string, string) (net.Conn, error)) {
	a.publications.SetDialer(dial)
}
func publicationActor(user User) publication.Actor {
	return publication.Actor{ID: user.ID, Admin: user.Role == "admin"}
}
func (a *App) registerPublicationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /publications", a.publicationPage)
	mux.HandleFunc("POST /publications", a.createPublication)
	mux.HandleFunc("GET /publications/{id}", a.publicationDetail)
	mux.HandleFunc("POST /publications/{id}/retry", a.retryPublication)
	mux.HandleFunc("POST /publications/{id}/disable", a.disablePublication)
	mux.HandleFunc("POST /publications/{id}/enable", a.enablePublication)
	mux.HandleFunc("POST /publications/{id}/delete", a.deletePublication)
}
func (a *App) publicationError(w http.ResponseWriter, err error) {
	var domainError *publication.Error
	if errors.As(err, &domainError) {
		status := map[publication.Kind]int{publication.Invalid: 400, publication.NotFound: 404, publication.Conflict: 409, publication.Unavailable: 503}[domainError.Kind]
		http.Error(w, domainError.Message, status)
		return
	}
	a.serverError(w, err)
}
func (a *App) publicationPage(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	view, err := a.publications.View(r.Context(), publicationActor(user))
	if err != nil {
		a.publicationError(w, err)
		return
	}
	csrf := randomToken()
	var body bytes.Buffer
	data := struct {
		CSRF string
		publication.View
	}{csrf, view}
	if err := template.Must(template.New("publications").Parse(publicationTemplate)).Execute(&body, data); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, csrfCookie, csrf, int(sessionLifetime.Seconds()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(body.Bytes())
}
func (a *App) createPublication(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	machineID, err := strconv.ParseInt(r.PostForm.Get("machine_id"), 10, 64)
	if err != nil {
		http.Error(w, "Выберите свою машину", 400)
		return
	}
	p, created, err := a.publications.Create(r.Context(), publicationActor(user), publication.CreateRequest{MachineID: machineID, Subdomain: r.PostForm.Get("subdomain"), Target: r.PostForm.Get("target")})
	if err != nil {
		a.publicationError(w, err)
		return
	}
	status := 200
	if created {
		status = 201
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/publications", 303)
		return
	}
	writeMachineJSON(w, status, p)
}
func (a *App) publicationDetail(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	p, err := a.publications.Get(r.Context(), publicationActor(user), r.PathValue("id"))
	if err != nil {
		a.publicationError(w, err)
		return
	}
	writeMachineJSON(w, 200, p)
}
func (a *App) retryPublication(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	if err := a.publications.Retry(r.Context(), publicationActor(user), r.PathValue("id")); err != nil {
		a.publicationError(w, err)
		return
	}
	http.Redirect(w, r, "/publications", 303)
}

func (a *App) disablePublication(w http.ResponseWriter, r *http.Request) {
	a.changePublicationAccess(w, r, false)
}
func (a *App) enablePublication(w http.ResponseWriter, r *http.Request) {
	a.changePublicationAccess(w, r, true)
}
func (a *App) changePublicationAccess(w http.ResponseWriter, r *http.Request, enabled bool) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if err != nil {
		http.Error(w, "Обновите страницу: некорректная версия публикации", 400)
		return
	}
	if err = a.publications.SetEnabled(r.Context(), publicationActor(user), publication.AccessChange{ID: r.PathValue("id"), Revision: revision, Enabled: enabled}); err != nil {
		a.publicationError(w, err)
		return
	}
	http.Redirect(w, r, "/publications", 303)
}

func (a *App) deletePublication(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if err != nil {
		http.Error(w, "Обновите страницу: некорректная версия публикации", 400)
		return
	}
	result, err := a.publications.Delete(r.Context(), publicationActor(user), publication.Deletion{ID: r.PathValue("id"), Revision: revision, ConfirmName: r.PostForm.Get("confirm_name")})
	if err != nil {
		a.publicationError(w, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/publications", 303)
		return
	}
	status := 202
	if result.Completed {
		status = 200
	}
	writeMachineJSON(w, status, result)
}

const publicationTemplate = `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Публикации — Среда</title><style>body{font:17px system-ui;max-width:850px;margin:40px auto;padding:0 24px;color:#16352b}article{border:1px solid #ccd9cf;padding:20px;border-radius:12px;margin:16px 0}input,select,button{font:inherit;padding:12px}label{display:block;margin:16px 0}button{background:#235c43;color:white;border:0;border-radius:8px}</style><a href="/">Кабинет</a> · <a href="/machines">Машины</a><h1>Публикации</h1>{{range .Publications}}<article><h2><a href="{{.URL}}">{{.URL}}</a></h2><p>Владелец: {{.Owner}} · Приложение: {{.Target}}</p><p>{{.State}}</p>{{if .CanDisable}}<form method="post" action="/publications/{{.ID}}/disable"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="revision" value="{{.Revision}}"><button>Отключить</button></form>{{end}}{{if .CanEnable}}<form method="post" action="/publications/{{.ID}}/enable"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="revision" value="{{.Revision}}"><button>Включить</button></form>{{end}}{{if .Error}}<p role="alert">{{.Error}}</p>{{if .CanRetry}}<form method="post" action="/publications/{{.ID}}/retry"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button>Повторить настройку</button></form>{{end}}{{end}}{{if .CanDelete}}<form method="post" action="/publications/{{.ID}}/delete"><input type="hidden" name="csrf" value="{{$.CSRF}}"><input type="hidden" name="revision" value="{{.Revision}}"><label>После удаления имя освободится и может быть занято другим человеком. Подтвердите потерю имени: введите {{.Subdomain}} <input name="confirm_name" required></label><button>{{if .DeletionPending}}Повторить удаление{{else}}Удалить навсегда{{end}}</button></form>{{end}}</article>{{else}}<p>Публикаций пока нет.</p>{{end}}{{if .Zone}}<h2>Опубликовать приложение</h2><form method="post" action="/publications"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Машина <select name="machine_id" required>{{range .Machines}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select></label><label>Адрес и порт приложения <input name="target" placeholder="127.0.0.1:8080" required></label><label>Поддомен <input name="subdomain" pattern="[a-z0-9][a-z0-9-]*" maxlength="63" required>.{{.Zone}}</label><button>Опубликовать</button></form><p>Укажите literal IP этой машины и порт HTTP-приложения. После подтверждения агентом появится статус «Настроена»; это не проверка здоровья приложения. Внешний адрес всегда HTTPS.</p>{{else}}<p>Оператор ещё не настроил общую доменную зону.</p>{{end}}</html>`
