// Package identity owns account access and one-time account credentials.
// It has no HTTP dependency. SQLite atomicity is private to the module.
package identity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"regexp"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const SessionLifetime = 12 * time.Hour
const passwordCost = 12

var loginPattern = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,63}$`)

// Failure is an expected application outcome. Transport adapters decide how it
// is presented; unexpected storage errors remain ordinary errors.
type Failure string

func (f Failure) Error() string { return string(f) }

const (
	Unauthenticated         Failure = "Требуется вход в кабинет"
	Forbidden               Failure = "Требуются права администратора"
	InvalidCredentials      Failure = "Неверный логин или пароль"
	InvalidLogin            Failure = "логин: 3–64 символа, латинские буквы, цифры, _, . или -; первый символ — буква или цифра"
	InvalidPassword         Failure = "пароль должен содержать от 12 до 72 байт"
	InvalidAccount          Failure = "Логин: 3–64 латинских символа, цифры, _, . или -; первый символ — буква или цифра. Пароль: 12–72 байта."
	InvalidLifetime         Failure = "Выберите срок: 1 час, 24 часа или 7 дней"
	InvitationInactive      Failure = "Приглашение недействительно или срок истёк"
	InvitationConflict      Failure = "Приглашение уже недействительно"
	LoginTaken              Failure = "Этот логин уже занят. Выберите другой; приглашение остаётся действующим."
	AdministratorLoginTaken Failure = "логин уже занят; существующая учётная запись не изменена"
	RecoveryInactive        Failure = "Ссылка восстановления недействительна или срок истёк"
	UserNotFound            Failure = "Обычный пользователь не найден"
	AdministratorNotFound   Failure = "администратор не найден"
)

type User struct {
	ID          int64
	Login, Role string
}
type Link struct {
	Token     string
	ExpiresAt time.Time
}
type InvitationState string

const (
	InvitationActive    InvitationState = "active"
	InvitationUsed      InvitationState = "used"
	InvitationCancelled InvitationState = "cancelled"
	InvitationExpired   InvitationState = "expired"
)

type Invitation struct {
	ID        int64
	ExpiresAt time.Time
	State     InvitationState
}

// Manager is composed with the existing database. It does not own its lifetime
// or migrations, which remain the application's composition responsibilities.
type Manager struct{ store sqliteStore }

func token() string {
	var raw [32]byte
	_, _ = rand.Read(raw[:])
	return base64.RawURLEncoding.EncodeToString(raw[:])
}
func tokenHash(token string) []byte      { sum := sha256.Sum256([]byte(token)); return sum[:] }
func validPassword(password string) bool { return len(password) >= 12 && len(password) <= 72 }
func passwordHash(password string) ([]byte, error) {
	if !validPassword(password) {
		return nil, InvalidPassword
	}
	return bcrypt.GenerateFromPassword([]byte(password), passwordCost)
}

var dummyPasswordHash = sync.OnceValue(func() []byte {
	hash, err := passwordHash("unused-account-password")
	if err != nil {
		panic(err)
	}
	return hash
})

func (m *Manager) CreateAdministrator(ctx context.Context, login, password string) error {
	if !loginPattern.MatchString(login) {
		return InvalidLogin
	}
	hash, err := passwordHash(password)
	if err != nil {
		return err
	}
	created, err := m.store.createAdministrator(ctx, login, hash)
	if err != nil {
		return fmt.Errorf("создание администратора: %w", err)
	}
	if !created {
		return AdministratorLoginTaken
	}
	return nil
}
func (m *Manager) ResetAdministratorPassword(ctx context.Context, login, password string) error {
	hash, err := passwordHash(password)
	if err != nil {
		return err
	}
	return m.store.resetAdministrator(ctx, login, hash)
}
func (m *Manager) SignIn(ctx context.Context, login, password, oldSession string) (string, error) {
	id, hash, err := m.store.credentials(ctx, login)
	if err != nil {
		return "", err
	}
	if id == 0 {
		hash = dummyPasswordHash()
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil || id == 0 || len(password) > 72 {
		return "", InvalidCredentials
	}
	next := token()
	now := time.Now()
	if err := m.store.rotateSession(ctx, id, hash, oldSession, next, now.Unix(), now.Add(SessionLifetime).Unix()); err != nil {
		return "", err
	}
	return next, nil
}
func (m *Manager) CurrentUser(ctx context.Context, session string) (User, error) {
	if session == "" {
		return User{}, Unauthenticated
	}
	return m.store.sessionUser(ctx, session, time.Now().Unix())
}
func (m *Manager) Administrator(ctx context.Context, session string) (User, error) {
	user, err := m.CurrentUser(ctx, session)
	if err != nil {
		return User{}, err
	}
	if user.Role != "admin" {
		return User{}, Forbidden
	}
	return user, nil
}
func (m *Manager) SignOut(ctx context.Context, session string) error {
	if session == "" {
		return nil
	}
	return m.store.deleteSession(ctx, session)
}
func (m *Manager) administratorID(ctx context.Context, id int64) error {
	role, err := m.store.userRole(ctx, id)
	if err != nil {
		return err
	}
	if role != "admin" {
		return Forbidden
	}
	return nil
}

func (m *Manager) Invitations(ctx context.Context, actorID int64) ([]Invitation, error) {
	if err := m.administratorID(ctx, actorID); err != nil {
		return nil, err
	}
	records, err := m.store.invitations(ctx)
	if err != nil {
		return nil, err
	}
	var result []Invitation
	now := time.Now().Unix()
	for _, record := range records {
		state := InvitationActive
		switch {
		case record.used:
			state = InvitationUsed
		case record.cancelled:
			state = InvitationCancelled
		case record.expiry <= now:
			state = InvitationExpired
		}
		result = append(result, Invitation{ID: record.id, ExpiresAt: time.Unix(record.expiry, 0), State: state})
	}
	return result, nil
}
func (m *Manager) IssueInvitation(ctx context.Context, actorID int64, lifetime string) (Link, error) {
	if err := m.administratorID(ctx, actorID); err != nil {
		return Link{}, err
	}
	duration, ok := map[string]time.Duration{"1h": time.Hour, "24h": 24 * time.Hour, "168h": 7 * 24 * time.Hour}[lifetime]
	if !ok {
		return Link{}, InvalidLifetime
	}
	link := Link{Token: token(), ExpiresAt: time.Now().Add(duration)}
	err := m.store.issueInvitation(ctx, actorID, link.Token, link.ExpiresAt.Unix())
	return link, err
}
func (m *Manager) CancelInvitation(ctx context.Context, actorID, id int64) error {
	if err := m.administratorID(ctx, actorID); err != nil {
		return err
	}
	return m.store.cancelInvitation(ctx, id, time.Now().Unix())
}
func (m *Manager) Invitation(ctx context.Context, token string) (time.Time, error) {
	expiry, err := m.store.invitationExpiry(ctx, token, time.Now().Unix())
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(expiry, 0), err
}
func (m *Manager) AcceptInvitation(ctx context.Context, token, login, password string) error {
	if _, err := m.Invitation(ctx, token); err != nil {
		return err
	}
	if !loginPattern.MatchString(login) || !validPassword(password) {
		return InvalidAccount
	}
	hash, err := passwordHash(password)
	if err != nil {
		return err
	}
	return m.store.acceptInvitation(ctx, token, login, hash, time.Now().Unix())
}
func (m *Manager) RecoveryUsers(ctx context.Context, actorID int64) ([]User, error) {
	if err := m.administratorID(ctx, actorID); err != nil {
		return nil, err
	}
	return m.store.ordinaryUsers(ctx)
}
func (m *Manager) IssueRecovery(ctx context.Context, actorID, userID int64) (Link, error) {
	if err := m.administratorID(ctx, actorID); err != nil {
		return Link{}, err
	}
	link := Link{Token: token(), ExpiresAt: time.Now().Add(time.Hour)}
	err := m.store.issueRecovery(ctx, userID, link.Token, link.ExpiresAt.Unix())
	return link, err
}
func (m *Manager) Recovery(ctx context.Context, token string) (time.Time, error) {
	expiry, err := m.store.recoveryExpiry(ctx, token, time.Now().Unix())
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(expiry, 0), err
}
func (m *Manager) RecoverPassword(ctx context.Context, token, password string) (time.Time, error) {
	expiry, err := m.Recovery(ctx, token)
	if err != nil {
		return expiry, err
	}
	hash, err := passwordHash(password)
	if err != nil {
		return expiry, err
	}
	return expiry, m.store.applyRecovery(ctx, token, hash, time.Now().Unix())
}
