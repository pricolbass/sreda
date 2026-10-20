package cabinet

import (
	"net/http"
	"strconv"
	"strings"
)

func (a *App) manualPublicKey(w http.ResponseWriter, r *http.Request) {
	u, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	params, err := a.agentControl.EnrollManual(r.Context(), machineActor(u), id, r.PostForm.Get("code"), r.PostForm.Get("public_key"))
	if err != nil {
		a.machineError(w, err)
		return
	}
	a.renderManual(w, http.StatusCreated, id, "", params)
}

func (a *App) manualTemplateDownload(w http.ResponseWriter, r *http.Request) {
	u, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	params, err := a.machines.ManualParameters(r.Context(), machineActor(u), id)
	if err != nil {
		a.machineError(w, err)
		return
	}
	config := params.ConfigurationTemplate()
	if config == "" {
		http.Error(w, "Сначала зарегистрируйте публичный ключ", 409)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="wg-sreda.conf"`)
	_, _ = w.Write([]byte(config))
}

func (a *App) manualParameters(w http.ResponseWriter, r *http.Request) {
	u, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	params, err := a.machines.ManualParameters(r.Context(), machineActor(u), id)
	if err != nil {
		a.machineError(w, err)
		return
	}
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		a.renderManual(w, http.StatusOK, params.ID, "", params)
		return
	}
	writeMachineJSON(w, 200, params)
}
