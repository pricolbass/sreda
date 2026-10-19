// Package machine owns machine ownership, enrollment and connection lifecycle.
// It has no HTTP knowledge. Kernel networking is supplied through tunnel.Gateway.
package machine

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"sreda/internal/tunnel"
	"strings"
	"sync"
	"time"
)

const CodeLifetime = 15 * time.Minute
const ContactLifetime = 90 * time.Second

type FailureKind int

const (
	Invalid FailureKind = iota
	NotFound
	Unauthorized
	Unavailable
)

type Failure struct {
	Kind    FailureKind
	Message string
}

func (e *Failure) Error() string                     { return e.Message }
func failure(kind FailureKind, message string) error { return &Failure{kind, message} }

type Actor struct {
	ID    int64
	Admin bool
}
type Record struct {
	ID, OwnerID int64
	Name, Owner string
	Enabled     bool
	Online      bool
	LastSeen    time.Time
}

// Connection includes credentials for trusted application modules. Never render it.
type Connection struct {
	ID, OwnerID                    int64
	PublicKey, Address, ProxyToken string
	Enabled                        bool
	LastSeen                       time.Time
}
type Enrollment struct {
	ID        int64
	Code      string
	ExpiresAt time.Time
}
type EnrollInput struct {
	Code       string `json:"code"`
	PublicKey  string `json:"public_key"`
	Credential string `json:"credential"`
}

type Manager struct {
	mu      sync.Mutex
	store   *sqliteStore
	gateway tunnel.Gateway
}

func (m *Manager) SetGateway(gateway tunnel.Gateway) { m.gateway = gateway }
func (m *Manager) GatewayDetails() (tunnel.Details, bool) {
	if m.gateway == nil {
		return tunnel.Details{}, false
	}
	return m.gateway.Details(), true
}
func (m *Manager) Create(ctx context.Context, actor Actor, name string) (Enrollment, error) {
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return Enrollment{}, failure(Invalid, "Название: от 1 до 100 байт")
	}
	if actor.ID <= 0 {
		return Enrollment{}, failure(Unauthorized, "Требуется вход")
	}
	enrollment := Enrollment{Code: token(), ExpiresAt: time.Now().Add(CodeLifetime)}
	id, err := m.store.create(ctx, actor.ID, name, hash(enrollment.Code), enrollment.ExpiresAt.Unix(), time.Now().Unix())
	enrollment.ID = id
	return enrollment, err
}
func (m *Manager) List(ctx context.Context, actor Actor) ([]Record, error) {
	records, err := m.store.list(ctx, actor)
	now := time.Now()
	for i := range records {
		records[i].Online = ContactIsOnline(records[i].Enabled, records[i].LastSeen, now)
	}
	return records, err
}
func (m *Manager) Find(ctx context.Context, actor Actor, id int64) (Record, error) {
	return m.store.find(ctx, actor, id)
}
func (m *Manager) Connection(ctx context.Context, id int64) (Connection, error) {
	return m.store.connection(ctx, id)
}
func validKey(key string) bool {
	raw, err := base64.StdEncoding.DecodeString(key)
	return err == nil && len(raw) == 32 && base64.StdEncoding.EncodeToString(raw) == key && !bytes.Equal(raw, make([]byte, 32))
}
func (m *Manager) Enroll(ctx context.Context, input EnrollInput) (Connection, error) {
	if len(input.Code) != 43 || len(input.Credential) != 43 || !validKey(input.PublicKey) {
		return Connection{}, failure(Invalid, "Неверные параметры подключения")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gateway == nil {
		return Connection{}, failure(Unavailable, "Сетевой шлюз не настроен; код сохранён")
	}
	if err := m.gateway.Details().Validate(); err != nil {
		return Connection{}, failure(Unavailable, "Сетевой шлюз настроен некорректно; код сохранён")
	}

	pool := make([]string, 0, 100)
	for i := 2; i <= 101; i++ {
		pool = append(pool, fmt.Sprintf("10.203.0.%d/32", i))
	}
	owner := token()
	now := time.Now()
	intent, err := m.store.reserveEnrollment(ctx, input, token(), owner, now.Unix(), now.Add(enrollmentLease).Unix(), pool)
	if err != nil {
		return Connection{}, err
	}
	if intent.phase == "cleanup" {
		if err := m.compensateEnrollment(intent); err != nil {
			return Connection{}, failure(Unavailable, "Очистка прежней попытки подключения не подтверждена; повторите позже")
		}
		now = time.Now()
		intent, err = m.store.reserveEnrollment(ctx, input, token(), owner, now.Unix(), now.Add(enrollmentLease).Unix(), pool)
		if err != nil {
			return Connection{}, err
		}
	}
	operationCtx, cancel := context.WithTimeout(ctx, enrollmentOperationTimeout)
	err = m.gateway.ApplyPeer(operationCtx, intent.peer())
	cancel()
	if err == nil {
		err = m.store.finalizeEnrollment(ctx, intent, time.Now().Unix())
	}
	if err != nil {
		cleanupErr := m.compensateEnrollment(intent)
		if cleanupErr != nil {
			return Connection{}, failure(Unavailable, "Подключение не завершено; очистка сети не подтверждена и будет повторена")
		}
		return Connection{}, failure(Unavailable, "Не удалось подтвердить настройку сети; повторите подключение")
	}
	intent.connection.Enabled = true
	return intent.connection, nil
}
func (m *Manager) AuthenticateAgent(ctx context.Context, credential string) (Connection, error) {
	if len(credential) != 43 || m.gateway == nil {
		return Connection{}, failure(Unauthorized, "Подключение недоступно")
	}
	return m.store.agent(ctx, hash(credential))
}
func (m *Manager) ObserveContact(ctx context.Context, id int64) error {
	return m.store.observe(ctx, id, time.Now().Unix())
}
func (m *Manager) SetEnabled(ctx context.Context, id int64, enabled bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	conn, err := m.store.connection(ctx, id)
	if err != nil {
		return err
	}
	if conn.PublicKey == "" {
		return failure(Invalid, "машина ещё не подключена")
	}
	if m.gateway == nil {
		return failure(Unavailable, "сетевой шлюз не настроен")
	}
	peer := tunnel.Peer{MachineID: conn.ID, PublicKey: conn.PublicKey, Address: conn.Address}
	if enabled {
		err = m.gateway.ApplyPeer(ctx, peer)
	} else {
		err = m.gateway.RemovePeer(ctx, peer)
	}
	if err != nil {
		return fmt.Errorf("не удалось подтвердить применение сетевых настроек: %w", err)
	}
	return m.store.setEnabled(ctx, id, enabled)
}
func (m *Manager) Reconcile(ctx context.Context) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.gateway == nil {
		return failure(Unavailable, "сетевой шлюз не настроен")
	}

	now := time.Now()
	intents, err := m.store.claimEnrollmentCleanup(ctx, token(), now.Unix(), now.Add(enrollmentLease).Unix(), enrollmentCleanupBatch)
	if err != nil {
		return err
	}
	var failures []error
	for _, intent := range intents {
		cleanupCtx, cancel := context.WithTimeout(ctx, enrollmentCleanupTimeout)
		err := m.cleanupEnrollment(cleanupCtx, intent, enrollmentCleanupTimeout)
		cancel()
		if err != nil {
			failures = append(failures, err)
		}
	}
	peers, err := m.store.enabledPeers(ctx)
	if err != nil {
		return errors.Join(append(failures, err)...)
	}
	for _, peer := range peers {
		if err := m.gateway.ApplyPeer(ctx, peer); err != nil {
			failures = append(failures, failure(Unavailable, "сетевой helper не подтвердил восстановление подключений"))
		}
	}
	return errors.Join(failures...)
}

const enrollmentOperationTimeout = 10 * time.Second
const enrollmentCleanupTimeout = 3 * time.Second
const enrollmentCleanupBatch = 2
const enrollmentLease = 45 * time.Second

func (intent enrollmentIntent) peer() tunnel.Peer {
	return tunnel.Peer{MachineID: intent.connection.ID, PublicKey: intent.connection.PublicKey, Address: intent.connection.Address}
}

// Compensation has its own bounded context: canceling an HTTP request must not
// cancel fail-closed cleanup or the record needed by the next reconciliation.
func (m *Manager) compensateEnrollment(intent enrollmentIntent) error {
	ctx, cancel := context.WithTimeout(context.Background(), enrollmentOperationTimeout)
	defer cancel()
	return m.cleanupEnrollment(ctx, intent, enrollmentOperationTimeout)
}
func (m *Manager) cleanupEnrollment(ctx context.Context, intent enrollmentIntent, releaseTimeout time.Duration) error {
	if err := m.store.markEnrollmentCleanup(ctx, intent, time.Now().Add(enrollmentLease).Unix()); err != nil {
		return err
	}
	err := m.gateway.RemovePeer(ctx, intent.peer())
	if err == nil {
		err = m.store.finishEnrollmentCleanup(ctx, intent)
	}
	if err != nil {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), releaseTimeout)
		defer releaseCancel()
		return errors.Join(err, m.store.releaseEnrollmentCleanup(releaseCtx, intent))
	}
	return nil
}

func token() string {
	var value [32]byte
	_, _ = rand.Read(value[:])
	return base64.RawURLEncoding.EncodeToString(value[:])
}
func hash(token string) []byte { value := sha256.Sum256([]byte(token)); return value[:] }

// ContactIsOnline is the shared control-contact policy; it does not assert application health.
func ContactIsOnline(enabled bool, lastSeen, now time.Time) bool {
	return enabled && !lastSeen.IsZero() && now.Sub(lastSeen) < ContactLifetime
}
