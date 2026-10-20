package cabinet

import (
	"fmt"
	"html/template"
	"net/http"
	"sreda/internal/machine"
	"sreda/internal/reconnection"
	"strconv"
	"strings"
)

func (a *App) reconnectMachine(w http.ResponseWriter, r *http.Request) {
	u, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	revision, err := strconv.ParseInt(r.PostForm.Get("revision"), 10, 64)
	if err != nil {
		http.Error(w, "Обновите страницу: некорректная версия подключения", 400)
		return
	}
	e, err := reconnection.New(a.machines, a.publications).Replace(r.Context(), machineActor(u), id, revision)
	if err != nil {
		a.machineError(w, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		if e.Mode == machine.ManualMode {
			a.renderManual(w, 201, e.ID, e.Code, machine.ManualParameters{})
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(201)
		fmt.Fprintf(w, `<!doctype html><html lang="ru"><meta charset="utf-8"><h1>Переподключить существующую машину</h1><p>Прежнее подключение отозвано. Новый код действует 15 минут и используется один раз.</p><code>%s</code><p>На этой машине запустите <code>sreda-agent enroll --origin %s</code> с новым локальным состоянием агента и введите код по запросу. Публикации и поддомены сохранены. Намеренно отключённые ресурсы нужно включить отдельно.</p><a href="/machines">Машины</a></html>`, template.HTMLEscapeString(e.Code), template.HTMLEscapeString(a.origin))
		return
	}
	writeMachineJSON(w, 201, map[string]any{"id": e.ID, "code": e.Code, "expires_at": e.ExpiresAt.Unix(), "mode": e.Mode})
}

func (a *App) recoverAgentState(w http.ResponseWriter, r *http.Request) {
	var input struct {
		PublicKey string `json:"public_key"`
	}
	if !readMachineJSON(w, r, &input) {
		return
	}
	control, err := a.agentControl.Recover(r.Context(), strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "), input.PublicKey)
	if err != nil {
		a.machineError(w, err)
		return
	}
	writeMachineJSON(w, 200, control)
}
