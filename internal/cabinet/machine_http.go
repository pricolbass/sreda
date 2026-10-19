package cabinet

import (
	"bytes"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"sreda/internal/agentprotocol"
	"sreda/internal/tunnel"
	"strconv"
	"strings"
	"time"
)

func (a *App) registerMachineRoutes(mux *http.ServeMux) {
	mux.HandleFunc("GET /machines", a.machinePage)
	mux.HandleFunc("POST /machines", a.createMachine)
	mux.HandleFunc("GET /machines/{id}", a.machineDetail)
	mux.HandleFunc("POST /api/agent/enroll", a.enrollMachine)
	mux.HandleFunc("POST /api/agent/heartbeat", a.machineHeartbeat)
}

type machineView struct {
	ID                           int64
	Name, Owner, State, LastSeen string
}

func (a *App) machinePage(w http.ResponseWriter, r *http.Request) {
	u, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	rows, err := a.db.QueryContext(r.Context(), `SELECT machines.id,name,users.login,enabled,last_seen FROM machines JOIN users ON users.id=owner_id WHERE owner_id=? OR ?='admin' ORDER BY machines.id`, u.ID, u.Role)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer rows.Close()
	views := []machineView{}
	for rows.Next() {
		var v machineView
		var enabled bool
		var last sql.NullInt64
		if err := rows.Scan(&v.ID, &v.Name, &v.Owner, &enabled, &last); err != nil {
			a.serverError(w, err)
			return
		}
		v.State = "Нет связи"
		v.LastSeen = "Ещё не было"
		if last.Valid {
			v.LastSeen = time.Unix(last.Int64, 0).UTC().Format("2006-01-02 15:04:05 UTC")
			if enabled && time.Since(time.Unix(last.Int64, 0)) < machineContactLifetime {
				v.State = "На связи"
			}
		}
		views = append(views, v)
	}
	if err := rows.Err(); err != nil {
		a.serverError(w, err)
		return
	}
	csrf := randomToken()
	var body bytes.Buffer
	data := struct {
		CSRF     string
		Machines []machineView
	}{csrf, views}
	if err := template.Must(template.New("machines").Parse(machineTemplate)).Execute(&body, data); err != nil {
		a.serverError(w, err)
		return
	}
	setCookie(w, csrfCookie, csrf, int(sessionLifetime.Seconds()))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(body.Bytes())
}
func (a *App) createMachine(w http.ResponseWriter, r *http.Request) {
	u, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	name := strings.TrimSpace(r.PostForm.Get("name"))
	if name == "" || len(name) > 100 {
		http.Error(w, "Название: от 1 до 100 байт", 400)
		return
	}
	code := randomToken()
	expires := time.Now().Add(connectionCodeLifetime).Unix()
	result, err := a.db.ExecContext(r.Context(), `INSERT INTO machines(owner_id,name,code_hash,code_expires_at,created_at) VALUES(?,?,?,?,?)`, u.ID, name, tokenHash(code), expires, time.Now().Unix())
	if err != nil {
		a.serverError(w, err)
		return
	}
	id, _ := result.LastInsertId()
	// JSON is also usable from the terminal; the HTML page offers a direct form.
	if strings.Contains(r.Header.Get("Accept"), "text/html") {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.WriteHeader(201)
		fmt.Fprintf(w, `<!doctype html><html lang="ru"><meta charset="utf-8"><title>Подключить машину</title><h1>Код подключения</h1><p>Действует 15 минут. Передайте только агенту этой машины.</p><code>%s</code><p>В терминале Debian: <code>sreda-agent enroll --origin %s</code> и введите код по запросу. См. инструкцию оператора по установке.</p><a href="/machines">К машинам</a></html>`, template.HTMLEscapeString(code), template.HTMLEscapeString(a.origin))
		return
	}
	writeMachineJSON(w, 201, map[string]any{"id": id, "code": code, "expires_at": expires})
}
func (a *App) machineDetail(w http.ResponseWriter, r *http.Request) {
	u, ok := a.currentUser(w, r)
	if !ok {
		return
	}
	id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	var v machineView
	err = a.db.QueryRowContext(r.Context(), `SELECT id,name FROM machines WHERE id=? AND (owner_id=? OR ?='admin')`, id, u.ID, u.Role).Scan(&v.ID, &v.Name)
	if errors.Is(err, sql.ErrNoRows) {
		http.NotFound(w, r)
		return
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	writeMachineJSON(w, 200, v)
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
	json.NewEncoder(w).Encode(value)
}

// AgentControl will gain routes in the publication slice. Generation prevents stale updates.
type AgentRoute = agentprotocol.Route
type AgentControl = agentprotocol.Control

func validPublicKey(key string) bool {
	raw, err := base64.StdEncoding.DecodeString(key)
	if err != nil || len(raw) != 32 || len(key) != 44 {
		return false
	}
	return !bytes.Equal(raw, make([]byte, 32))
}
func (a *App) enrollMachine(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Code       string `json:"code"`
		PublicKey  string `json:"public_key"`
		Credential string `json:"credential"`
	}
	if !readMachineJSON(w, r, &input) {
		return
	}
	if len(input.Code) != 43 || len(input.Credential) != 43 || !validPublicKey(input.PublicKey) {
		http.Error(w, "Неверные параметры подключения", 400)
		return
	}
	a.machines.mu.Lock()
	defer a.machines.mu.Unlock()
	if a.machines.gateway == nil {
		http.Error(w, "Сетевой шлюз не настроен; код сохранён", 503)
		return
	}
	if err := a.machines.gateway.Details().Validate(); err != nil {
		http.Error(w, "Сетевой шлюз настроен некорректно; код сохранён", 503)
		return
	}
	tx, err := a.db.BeginTx(r.Context(), nil)
	if err != nil {
		a.serverError(w, err)
		return
	}
	defer tx.Rollback()
	var m MachineConnection
	err = tx.QueryRowContext(r.Context(), `SELECT id,owner_id FROM machines WHERE code_hash=? AND code_expires_at>? AND credential_hash IS NULL`, tokenHash(input.Code), time.Now().Unix()).Scan(&m.ID, &m.OwnerID)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Код недействителен или уже использован", 401)
		return
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	rows, err := tx.QueryContext(r.Context(), "SELECT tunnel_address FROM machines WHERE tunnel_address IS NOT NULL")
	if err != nil {
		a.serverError(w, err)
		return
	}
	used := map[string]bool{}
	for rows.Next() {
		var address string
		if err = rows.Scan(&address); err != nil {
			rows.Close()
			a.serverError(w, err)
			return
		}
		used[address] = true
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		a.serverError(w, err)
		return
	}
	for address := 2; address <= 101; address++ {
		candidate := fmt.Sprintf("10.203.0.%d/32", address)
		if !used[candidate] {
			m.Address = candidate
			break
		}
	}
	if m.Address == "" {
		http.Error(w, "Исчерпан пул из 100 подключений", 503)
		return
	}
	m.PublicKey = input.PublicKey
	m.ProxyToken = randomToken()
	m.Enabled = true
	peer := tunnel.Peer{MachineID: m.ID, PublicKey: m.PublicKey, Address: m.Address}
	if err = a.machines.gateway.ApplyPeer(r.Context(), peer); err != nil {
		http.Error(w, "Не удалось подтвердить настройку сети; повторите подключение", 503)
		return
	}
	_, err = tx.ExecContext(r.Context(), `UPDATE machines SET code_hash=NULL,code_expires_at=NULL,credential_hash=?,public_key=?,tunnel_address=?,proxy_token=?,enabled=1 WHERE id=?`, tokenHash(input.Credential), m.PublicKey, m.Address, m.ProxyToken, m.ID)
	if err == nil {
		err = tx.Commit()
	}
	if err != nil {
		_ = a.machines.gateway.RemovePeer(r.Context(), peer)
		http.Error(w, "Не удалось сохранить подключение", 500)
		return
	}
	control, err := a.controlFor(m)
	if err != nil {
		a.serverError(w, err)
		return
	}
	writeMachineJSON(w, 201, control)
}
func (a *App) machineHeartbeat(w http.ResponseWriter, r *http.Request) {
	var input struct {
		Ready             bool   `json:"ready"`
		AppliedGeneration uint64 `json:"applied_generation"`
		FailedGeneration  uint64 `json:"failed_generation"`
		ApplyError        string `json:"apply_error"`
	}
	if !readMachineJSON(w, r, &input) {
		return
	}
	token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	if len(token) != 43 || a.machines.gateway == nil {
		http.Error(w, "Подключение недоступно", 401)
		return
	}
	var m MachineConnection
	err := a.db.QueryRowContext(r.Context(), `SELECT id,owner_id,public_key,tunnel_address,proxy_token,enabled FROM machines WHERE credential_hash=? AND enabled=1`, tokenHash(token)).Scan(&m.ID, &m.OwnerID, &m.PublicKey, &m.Address, &m.ProxyToken, &m.Enabled)
	if errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Подключение отключено или отозвано", 401)
		return
	}
	if err != nil {
		a.serverError(w, err)
		return
	}
	if input.Ready {
		if _, err = a.db.ExecContext(r.Context(), "UPDATE machines SET last_seen=? WHERE id=? AND enabled=1", time.Now().Unix(), m.ID); err != nil {
			a.serverError(w, err)
			return
		}
	}
	a.publications.mu.Lock()
	defer a.publications.mu.Unlock()
	if input.Ready {
		if err := a.recordAgentAcknowledgment(r.Context(), m.ID, input.AppliedGeneration, input.FailedGeneration, input.ApplyError); err != nil {
			http.Error(w, "Не удалось подтвердить версию маршрутов", 409)
			return
		}
	}
	control, err := a.controlFor(m)
	if err != nil {
		a.serverError(w, err)
		return
	}
	writeMachineJSON(w, 200, control)
}

const machineTemplate = `<!doctype html><html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Машины — Среда</title><style>body{font:17px system-ui;max-width:850px;margin:40px auto;padding:0 24px;color:#16352b}article{border:1px solid #ccd9cf;padding:20px;border-radius:12px;margin:16px 0}input,button{font:inherit;padding:12px}button{background:#235c43;color:white;border:0;border-radius:8px}</style><a href="/">Кабинет</a><h1>Машины</h1>{{range .Machines}}<article><h2>{{.Name}}</h2><p>Владелец: {{.Owner}}</p><p>{{.State}}</p><p>Последний контакт: {{.LastSeen}}</p></article>{{else}}<p>Добавьте свою машину, чтобы подключить агент.</p>{{end}}<h2>Добавить машину</h2><form method="post" action="/machines"><input type="hidden" name="csrf" value="{{.CSRF}}"><label>Название <input name="name" maxlength="100" required></label> <button>Получить код подключения</button></form><p>Поддерживается Debian 12/13 LXC с systemd и доступом к WireGuard. Код действует 15 минут и показывается один раз. Время контакта относится к управляющему соединению агента.</p></html>`
