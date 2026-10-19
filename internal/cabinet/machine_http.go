package cabinet

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sreda/internal/agentcontrol"
	"sreda/internal/machine"
	"sreda/internal/publication"
	"strconv"
	"strings"
)

func (a *App) registerMachineRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /machines", a.machinePage)
	mux.HandleFunc("POST /machines", a.createMachine)
	mux.HandleFunc("GET /machines/{id}", a.machineDetail)
	mux.HandleFunc("POST /machines/{id}/delete", a.deleteMachine)
	mux.HandleFunc("POST /api/agent/enroll", a.enrollMachine)
	mux.HandleFunc("POST /api/agent/heartbeat", a.machineHeartbeat)
}

type machineView struct {
	ID                                  int64
	Name, Owner, State, LastSeen, Error string
	CanDelete                           bool
}

func machineActor(user User) machine.Actor {
	return machine.Actor{ID: user.ID, Admin: user.Role == "admin"}
}
func (a *App) machineError(w http.ResponseWriter, err error) {
	var blockers *machine.BlockedDeletion
	if errors.As(err, &blockers) {
		http.Error(w, blockers.Error(), 409)
		return
	}
	var publicationFailure *publication.Error
	if errors.As(err, &publicationFailure) {
		a.publicationError(w, err)
		return
	}
	var failure *machine.Failure
	if !errors.As(err, &failure) {
		a.serverError(w, err)
		return
	}
	status := http.StatusBadRequest
	switch failure.Kind {
	case machine.NotFound:
		status = 404
	case machine.Unauthorized:
		status = 401
	case machine.Unavailable:
		status = 503
	}
	http.Error(w, failure.Message, status)
}
func (a *App) machinePage(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	records, err := a.machines.List(r.Context(), machineActor(user))
	if err != nil {
		a.machineError(w, err)
		return
	}
	views := []machineView{}
	for _, record := range records {
		view := machineView{ID: record.ID, Name: record.Name, Owner: record.Owner, State: "Нет связи", LastSeen: "Ещё не было", Error: record.DeleteError, CanDelete: record.OwnerID == user.ID}
		if !record.LastSeen.IsZero() {
			view.LastSeen = record.LastSeen.UTC().Format("2006-01-02 15:04:05 UTC")
			if record.Online {
				view.State = "На связи"
			}
		}
		if record.DeletionPending {
			view.State = "Удаляется"
		}
		views = append(views, view)
	}
	csrf := randomToken()
	var body bytes.Buffer
	data := struct {
		CSRF     string
		Machines []machineView
	}{csrf, views}
	if err = template.Must(template.New("machines").Parse(machineTemplate)).Execute(&body, data); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, csrfCookie, csrf, int(sessionLifetime.Seconds()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = w.Write(body.Bytes())
}
func (a *App) createMachine(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	enrollment, err := a.machines.Create(r.Context(), machineActor(user), r.PostForm.Get("name"))
	if err != nil {
		a.machineError(w, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(201)
		fmt.Fprintf(w, `<!doctype html><html lang="ru"><meta charset="utf-8"><title>Подключить машину</title><h1>Код подключения</h1><p>Действует 15 минут. Передайте только агенту этой машины.</p><code>%s</code><p>В терминале Debian: <code>sreda-agent enroll --origin %s</code> и введите код по запросу. См. инструкцию оператора по установке.</p><a href="/machines">К машинам</a></html>`, template.HTMLEscapeString(enrollment.Code), template.HTMLEscapeString(a.origin))
		return
	}
	writeMachineJSON(w, 201, map[string]any{"id": enrollment.ID, "code": enrollment.Code, "expires_at": enrollment.ExpiresAt.Unix()})
}
func (a *App) machineDetail(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	record, err := a.machines.Find(r.Context(), machineActor(user), id)
	if err != nil {
		a.machineError(w, err)
		return
	}
	writeMachineJSON(w, 200, machineView{ID: record.ID, Name: record.Name})
}
func readMachineJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	if r.Header.Get("Content-Type") != "application/json" {
		http.Error(w, "Требуется JSON", 415)
		return false
	}
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(value); err != nil {
		http.Error(w, "Некорректный запрос", 400)
		return false
	}
	if decoder.Decode(new(any)) != io.EOF {
		http.Error(w, "Некорректный запрос", 400)
		return false
	}
	return true
}
func writeMachineJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func (a *App) enrollMachine(w http.ResponseWriter, r *http.Request) {
	var input machine.EnrollInput
	if !readMachineJSON(w, r, &input) {
		return
	}
	control, err := a.agentControl.Enroll(r.Context(), input)
	if err != nil {
		a.machineError(w, err)
		return
	}
	writeMachineJSON(w, 201, control)
}
func (a *App) machineHeartbeat(w http.ResponseWriter, r *http.Request) {
	var input agentcontrol.Heartbeat
	if !readMachineJSON(w, r, &input) {
		return
	}
	control, err := a.agentControl.Heartbeat(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), input)
	if err != nil {
		a.machineError(w, err)
		return
	}
	writeMachineJSON(w, 200, control)
}

func (a *App) deleteMachine(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	result, err := a.machines.Delete(r.Context(), machineActor(user), id)
	if err != nil {
		a.machineError(w, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		http.Redirect(w, r, "/machines", 303)
		return
	}
	status := 202
	if result.Completed {
		status = 200
	}
	writeMachineJSON(w, status, result)
}

const machineTemplate = `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Машины — Среда</title><style>body{font:17px system-ui;max-width:850px;margin:40px auto;padding:0 24px;color:#16352b}article{border:1px solid #ccd9cf;padding:20px;border-radius:12px;margin:16px 0}input,button{font:inherit;padding:12px}button{background:#235c43;color:white;border:0;border-radius:8px}</style><a href="/">Кабинет</a><h1>Машины</h1>{{range .Machines}}<article><h2>{{.Name}}</h2><p>Владелец: {{.Owner}}</p><p>{{.State}}</p><p>Последний контакт: {{.LastSeen}}</p>{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}{{if .CanDelete}}<form method="post" action="/machines/{{.ID}}/delete"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button>Удалить машину</button></form>{{end}}</article>{{else}}<p>Добавьте свою машину, чтобы подключить агент.</p>{{end}}<h2>Добавить машину</h2><form method="post" action="/machines"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Название <input name="name" maxlength="100" required></label> <button>Получить код подключения</button></form><p>Поддерживается Debian 12/13 LXC с systemd и доступом к WireGuard. Код действует 15 минут и показывается один раз. Время контакта относится к управляющему соединению агента.</p></html>`
