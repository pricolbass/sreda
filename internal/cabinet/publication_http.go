package cabinet

import (
	"bytes"
	"database/sql"
	"errors"
	"html/template"
	"net/http"
	"strconv"
	"strings"
	"time"
)

func (a *App) registerPublicationRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /publications", a.publicationPage)
	mux.HandleFunc("POST /publications", a.createPublication)
	mux.HandleFunc("GET /publications/{id}", a.publicationDetail)
	mux.HandleFunc("POST /publications/{id}/retry", a.retryPublication)
}
func (a *App) publicationPage(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT `+publicationColumns+` FROM publications p JOIN machines m ON m.id=p.machine_id JOIN users u ON u.id=m.owner_id WHERE m.owner_id=? OR ?='admin' ORDER BY p.created_at,p.id`, user.ID, user.Role)
	if err != nil {
		a.serverError(w, err)
		return
	}
	pubs := []Publication{}
	for rows.Next() {
		var p Publication
		if err := rows.Scan(&p.ID, &p.MachineID, &p.Subdomain, &p.Target, &p.State, &p.Error, &p.Revision, &p.Owner); err != nil {
			rows.Close()
			a.serverError(w, err)
			return
		}
		p.URL = "https://" + p.Subdomain + "." + a.publications.zone
		pubs = append(pubs, p)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		a.serverError(w, err)
		return
	}
	rows, err = a.db.QueryContext(r.Context(), "SELECT id,name FROM machines WHERE owner_id=? AND enabled=1 ORDER BY id", user.ID)
	if err != nil {
		a.serverError(w, err)
		return
	}
	machines := []machineView{}
	for rows.Next() {
		var m machineView
		if err := rows.Scan(&m.ID, &m.Name); err != nil {
			rows.Close()
			a.serverError(w, err)
			return
		}
		machines = append(machines, m)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		a.serverError(w, err)
		return
	}
	csrf := randomToken()
	data := struct {
		CSRF, Zone   string
		Publications []Publication
		Machines     []machineView
	}{csrf, a.publications.zone, pubs, machines}
	var body bytes.Buffer
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
	if a.publications.zone == "" {
		http.Error(w, "Оператор ещё не настроил общую доменную зону", 503)
		return
	}
	machineID, err := strconv.ParseInt(r.PostForm.Get("machine_id"), 10, 64)
	if err != nil {
		http.Error(w, "Выберите свою машину", 400)
		return
	}
	label := r.PostForm.Get("subdomain")
	target := r.PostForm.Get("target")
	if !subdomainPattern.MatchString(label) || a.reservedSubdomain(label) {
		http.Error(w, "Недопустимый или зарезервированный поддомен", 400)
		return
	}
	if err := validatePublicationTarget(target); err != nil {
		http.Error(w, err.Error(), 400)
		return
	}
	a.publications.mu.Lock()
	defer a.publications.mu.Unlock()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer tx.Rollback()
	var enabled bool
	var key sql.NullString
	err = tx.QueryRowContext(r.Context(), "SELECT enabled,public_key FROM machines WHERE id=? AND owner_id=?", machineID, user.ID).Scan(&enabled, &key)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	if !enabled || !key.Valid {
		http.Error(w, "Сначала подключите машину", 409)
		return
	}
	var oldID, oldTarget string
	var oldMachine int64
	err = tx.QueryRowContext(r.Context(), "SELECT id,machine_id,target FROM publications WHERE subdomain=?", label).Scan(&oldID, &oldMachine, &oldTarget)
	if err == nil {
		if oldMachine == machineID && oldTarget == target {
			tx.Rollback()
			p, err := a.publicationFromRow(a.db.QueryRowContext(r.Context(), `SELECT `+publicationColumns+` FROM publications p JOIN machines m ON m.id=p.machine_id JOIN users u ON u.id=m.owner_id WHERE p.id=?`, oldID))
			if err != nil {
				a.serverError(w, err)
				return
			}
			a.respondPublication(w, r, 200, p)
			return
		}
		http.Error(w, "Поддомен уже занят", 409)
		return
	}
	if !errors.Is(err, sql.ErrNoRows) {
		a.serverError(w, err)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "INSERT OR IGNORE INTO machine_control(machine_id) VALUES(?)", machineID); err == nil {
		_, err = tx.ExecContext(r.Context(), "UPDATE machine_control SET generation=generation+1 WHERE machine_id=?", machineID)
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	var generation uint64
	if err = tx.QueryRowContext(r.Context(), "SELECT generation FROM machine_control WHERE machine_id=?", machineID).Scan(&generation); err != nil {
		a.serverError(w, err)
		return
	}
	p := Publication{ID: randomToken(), MachineID: machineID, Subdomain: label, Target: target, URL: "https://" + label + "." + a.publications.zone, State: "Настраивается", Revision: 1, Owner: user.Login}
	if _, err = tx.ExecContext(r.Context(), "INSERT INTO publications(id,machine_id,subdomain,target,state,generation,created_at) VALUES(?,?,?,?,?,?,?)", p.ID, machineID, label, target, p.State, generation, time.Now().Unix()); err != nil {
		a.serverError(w, err)
		return
	}
	if err = tx.Commit(); err != nil {
		a.serverError(w, err)
		return
	}
	a.respondPublication(w, r, 201, p)
}
func (a *App) respondPublication(w http.ResponseWriter, r *http.Request, status int, p Publication) {
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
	p, err := a.publicationFromRow(a.db.QueryRowContext(r.Context(), `SELECT `+publicationColumns+` FROM publications p JOIN machines m ON m.id=p.machine_id JOIN users u ON u.id=m.owner_id WHERE p.id=? AND (m.owner_id=? OR ?='admin')`, r.PathValue("id"), user.ID, user.Role))
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	writeMachineJSON(w, 200, p)
}
func (a *App) retryPublication(w http.ResponseWriter, r *http.Request) {
	user, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	a.publications.mu.Lock()
	defer a.publications.mu.Unlock()
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer tx.Rollback()
	var machineID int64
	var state string
	err = tx.QueryRowContext(r.Context(), `SELECT p.machine_id,p.state FROM publications p JOIN machines m ON m.id=p.machine_id WHERE p.id=? AND m.owner_id=? AND p.desired_enabled=1 AND m.enabled=1`, r.PathValue("id"), user.ID).Scan(&machineID, &state)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	if state != "Ошибка" {
		http.Redirect(w, r, "/publications", 303)
		return
	}
	if _, err = tx.ExecContext(r.Context(), "UPDATE machine_control SET generation=generation+1 WHERE machine_id=?", machineID); err == nil {
		_, err = tx.ExecContext(r.Context(), "UPDATE publications SET state='Настраивается',error='',generation=(SELECT generation FROM machine_control WHERE machine_id=?) WHERE id=?", machineID, r.PathValue("id"))
	}
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	http.Redirect(w, r, "/publications", 303)
}

const publicationTemplate = `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Публикации — Среда</title><style>body{font:17px system-ui;max-width:850px;margin:40px auto;padding:0 24px;color:#16352b}article{border:1px solid #ccd9cf;padding:20px;border-radius:12px;margin:16px 0}input,select,button{font:inherit;padding:12px}label{display:block;margin:16px 0}button{background:#235c43;color:white;border:0;border-radius:8px}</style><a href="/">Кабинет</a> · <a href="/machines">Машины</a><h1>Публикации</h1>{{range .Publications}}<article><h2><a href="{{.URL}}">{{.URL}}</a></h2><p>Владелец: {{.Owner}} · Приложение: {{.Target}}</p><p>{{.State}}</p>{{if .Error}}<p role="alert">{{.Error}}</p><form method="post" action="/publications/{{.ID}}/retry"><input type="hidden" name="csrf" value="{{$.CSRF}}"><button>Повторить настройку</button></form>{{end}}</article>{{else}}<p>Публикаций пока нет.</p>{{end}}{{if .Zone}}<h2>Опубликовать приложение</h2><form method="post" action="/publications"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Машина <select name="machine_id" required>{{range .Machines}}<option value="{{.ID}}">{{.Name}}</option>{{end}}</select></label><label>Адрес и порт приложения <input name="target" placeholder="127.0.0.1:8080" required></label><label>Поддомен <input name="subdomain" pattern="[a-z0-9][a-z0-9-]*" maxlength="63" required>.{{.Zone}}</label><button>Опубликовать</button></form><p>Укажите literal IP этой машины и порт HTTP-приложения. После подтверждения агентом появится статус «Настроена»; это не проверка здоровья приложения. Внешний адрес всегда HTTPS.</p>{{else}}<p>Оператор ещё не настроил общую доменную зону.</p>{{end}}</html>`
