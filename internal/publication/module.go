// Package publication owns publication authorization, lifecycle and forwarding.
// HTTP callers provide an actor and product intent; no SQL or transition ordering
// is part of the module interface.
package publication

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"errors"
	"net"
	"regexp"
	"sreda/internal/agentprotocol"
	"strings"
	"sync"
	"time"
)

type Actor struct {
	ID    int64
	Admin bool
}
type Publication struct {
	ID              string `json:"id"`
	MachineID       int64  `json:"machine_id"`
	Subdomain       string `json:"subdomain"`
	Target          string `json:"target"`
	URL             string `json:"url"`
	State           string `json:"state"`
	Error           string `json:"error"`
	Revision        int64  `json:"revision"`
	Owner           string `json:"owner"`
	OwnerID         int64  `json:"-"`
	DesiredEnabled  bool   `json:"enabled"`
	CanEnable       bool   `json:"can_enable"`
	CanDisable      bool   `json:"can_disable"`
	CanRetry        bool   `json:"can_retry"`
	DeletionPending bool   `json:"deleting"`
	CanDelete       bool   `json:"can_delete"`
}
type Machine struct {
	ID   int64
	Name string
}
type View struct {
	Zone         string
	Publications []Publication
	Machines     []Machine
}
type CreateRequest struct {
	MachineID         int64
	Subdomain, Target string
}
type Acknowledgment = agentprotocol.Acknowledgment

type Kind int

const (
	Invalid Kind = iota + 1
	NotFound
	Conflict
	Unavailable
)

type Error struct {
	Kind    Kind
	Message string
}

func (e *Error) Error() string             { return e.Message }
func fail(kind Kind, message string) error { return &Error{kind, message} }

type Module struct {
	mu                sync.Mutex
	store             *sqliteStore
	zone, cabinetHost string
	forwarder         *forwarder
	transport         Transport
	contactObserver   ContactObserver
	now               func() time.Time
}

type ContactObserver interface {
	ObserveConnection(context.Context, int64) error
}

// SetContactObserver composes the manual handshake observation adapter before
// requests are served. Its cache is owned by the machine application module.
func (m *Module) SetContactObserver(observer ContactObserver) { m.contactObserver = observer }

func New(db *sql.DB, cabinetHost string, transport Transport, now func() time.Time) (*Module, error) {
	if now == nil {
		now = time.Now
	}
	if transport == nil {
		return nil, errors.New("укажите транспорт публикаций")
	}
	store := &sqliteStore{db}
	zone, err := store.zone(context.Background())
	if err != nil {
		return nil, err
	}
	return &Module{store: store, zone: zone, cabinetHost: cabinetHost, forwarder: newForwarder(), transport: transport, now: now}, nil
}

var domainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$`)
var subdomainPattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

func (m *Module) ConfigureZone(ctx context.Context, zone string) error {
	if len(zone) > 253 || !domainPattern.MatchString(zone) {
		return fail(Invalid, "укажите общую доменную зону строчными буквами, без https и пути")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	saved, err := m.store.zone(ctx)
	if err != nil {
		return err
	}
	if saved != "" && saved != zone {
		return fail(Conflict, "доменная зона отличается от сохранённой")
	}
	actual, err := m.store.saveZone(ctx, zone)
	if err != nil {
		return err
	}
	if actual != zone {
		return fail(Conflict, "доменная зона отличается от сохранённой")
	}
	m.zone = actual
	return nil
}
func (m *Module) SetDialer(dial func(context.Context, string, string) (net.Conn, error)) {
	m.forwarder.dial = dial
}
func (m *Module) Create(ctx context.Context, actor Actor, input CreateRequest) (Publication, bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.zone == "" {
		return Publication{}, false, fail(Unavailable, "Оператор ещё не настроил общую доменную зону")
	}
	host := m.cabinetHost
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if !subdomainPattern.MatchString(input.Subdomain) || input.Subdomain+"."+m.zone == strings.ToLower(host) {
		return Publication{}, false, fail(Invalid, "Недопустимый или зарезервированный поддомен")
	}
	p, created, err := m.store.schedule(ctx, input, func(machine machineEligibility, existing *Publication) (creationDecision, error) {
		if machine.ID == 0 || machine.OwnerID != actor.ID {
			return creationDecision{}, fail(NotFound, "Машина не найдена")
		}
		if !machine.Enabled || !machine.Enrolled {
			return creationDecision{}, fail(Conflict, "Сначала подключите машину")
		}
		endpoint, err := m.transport.Endpoint(Connection{Mode: machine.Mode, Address: machine.Address, ProxyToken: machine.ProxyToken, Target: input.Target})
		if err != nil {
			return creationDecision{}, fail(Invalid, err.Error())
		}
		if existing != nil {
			if existing.MachineID == input.MachineID && existing.Target == input.Target {
				return creationDecision{Publication: *existing, Existing: true}, nil
			}
			return creationDecision{}, fail(Conflict, "Поддомен уже занят")
		}
		state := "Настраивается"
		if !endpoint.AgentControlled {
			state = "Настроена"
		}
		return creationDecision{Publication: Publication{ID: newPublicationID(), MachineID: input.MachineID, Subdomain: input.Subdomain, Target: input.Target, State: state, Revision: 1, Owner: machine.Login, OwnerID: machine.OwnerID, DesiredEnabled: true}}, nil
	})
	m.decorate(&p, actor)
	return p, created, err
}
func (m *Module) View(ctx context.Context, actor Actor) (View, error) {
	view, err := m.store.view(ctx, actor)
	view.Zone = m.zone
	for i := range view.Publications {
		m.decorate(&view.Publications[i], actor)
	}
	return view, err
}
func (m *Module) Get(ctx context.Context, actor Actor, id string) (Publication, error) {
	p, err := m.store.get(ctx, actor, id)
	m.decorate(&p, actor)
	return p, err
}
func (m *Module) Retry(ctx context.Context, actor Actor, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.retry(ctx, id, "Настраивается", func(candidate retryCandidate) (bool, error) {
		if candidate.OwnerID != actor.ID || !candidate.Desired || !candidate.Enabled {
			return false, fail(NotFound, "Публикация не найдена")
		}
		return candidate.State == "Ошибка", nil
	})
}
func (m *Module) Control(ctx context.Context, identity agentprotocol.ConnectionIdentity) (uint64, []agentprotocol.Route, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.store.control(ctx, identity)
}
func (m *Module) Acknowledge(ctx context.Context, identity agentprotocol.ConnectionIdentity, ack Acknowledgment) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if ack.Applied > 1<<62 || ack.Failed > 1<<62 {
		return fail(Invalid, "недопустимая версия маршрутов")
	}
	if len(ack.Error) > 300 {
		ack.Error = "Агент не смог применить маршруты"
	}
	if ack.Error == "" {
		ack.Error = "Агент не подтвердил применение маршрутов"
	}
	return m.store.acknowledge(ctx, identity, ack, func(generation, previous uint64) (acknowledgmentPlan, error) {
		if ack.Applied > generation || ack.Failed > generation {
			return acknowledgmentPlan{}, fail(Conflict, "неизвестная версия маршрутов")
		}
		return acknowledgmentPlan{Ready: ack.Applied >= previous, Failed: ack.Failed > ack.Applied && ack.Failed > previous && ack.Failed == generation, ReadyState: "Настроена", FailedState: "Ошибка"}, nil
	})
}
func (m *Module) url(label string) string {
	host := label + "." + m.zone
	if port := m.httpsPort(); port != "443" {
		host = net.JoinHostPort(host, port)
	}
	return "https://" + host
}

// The single HTTPS listener serves the cabinet and publications on one port.
func (m *Module) httpsPort() string {
	if _, port, err := net.SplitHostPort(m.cabinetHost); err == nil {
		return port
	}
	return "443"
}
func (m *Module) Close(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	var result error
	for id := range m.forwarder.routes {
		result = errors.Join(result, m.forwarder.close(ctx, id))
	}
	return result
}

func newPublicationID() string {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}

func (m *Module) decorate(p *Publication, actor Actor) {
	p.URL = m.url(p.Subdomain)
	p.CanDelete = p.OwnerID == actor.ID
	if p.DeletionPending {
		p.CanDisable = false
		p.CanEnable = false
		p.CanRetry = false
		return
	}
	p.CanDisable = (p.OwnerID == actor.ID || actor.Admin) && p.State != "Отключена"
	p.CanEnable = p.OwnerID == actor.ID && p.State == "Отключена"
	p.CanRetry = p.OwnerID == actor.ID && p.DesiredEnabled && p.State == "Ошибка"
}
