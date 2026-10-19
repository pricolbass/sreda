package machine

import (
	"context"
	"encoding/base64"
	"fmt"
	"sreda/internal/tunnel"
	"strings"
	"time"
)

type Mode string

const (
	AgentMode  Mode = "agent"
	ManualMode Mode = "manual"
)

// CreateWithMode fixes the connection mode before a code can be used. Empty mode
// retains the existing agent flow; later enrollment cannot override this choice.
func (m *Manager) CreateWithMode(ctx context.Context, actor Actor, name string, mode Mode) (Enrollment, error) {
	if mode == "" {
		mode = AgentMode
	}
	if mode != ManualMode && mode != AgentMode {
		return Enrollment{}, failure(Invalid, "Неизвестный способ подключения")
	}
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 100 {
		return Enrollment{}, failure(Invalid, "Название: от 1 до 100 байт")
	}
	if actor.ID <= 0 {
		return Enrollment{}, failure(Unauthorized, "Требуется вход")
	}
	enrollment := Enrollment{Code: token(), ExpiresAt: time.Now().Add(CodeLifetime), Mode: mode}
	id, err := m.store.createWithMode(ctx, actor.ID, name, mode, hash(enrollment.Code), enrollment.ExpiresAt.Unix(), time.Now().Unix())
	enrollment.ID = id
	return enrollment, err
}

func enrollmentProxyToken(mode Mode) string {
	if mode == ManualMode {
		return ""
	}
	return token()
}

// ManualParameters contains only public connection parameters. Neither browser
// downloads nor later configuration prompts can accidentally serialize a token.
type ManualParameters struct {
	ID        int64          `json:"machine_id"`
	Name      string         `json:"name"`
	PublicKey string         `json:"public_key"`
	Address   string         `json:"address"`
	Tunnel    tunnel.Details `json:"tunnel"`
	Enabled   bool           `json:"enabled"`
}

func (m *Manager) ManualParameters(ctx context.Context, actor Actor, id int64) (ManualParameters, error) {
	params, err := m.store.manualParameters(ctx, actor, id)
	if err != nil {
		return params, err
	}
	details, ok := m.GatewayDetails()
	if !ok || details.Validate() != nil {
		return params, failure(Unavailable, "Параметры WireGuard шлюза пока недоступны")
	}
	params.Tunnel = details
	return params, nil
}

// ConfigurationTemplate never contains a client private key. It is completed
// locally when browser key generation is unsupported.
func (p ManualParameters) ConfigurationTemplate() string {
	if p.Address == "" || p.Tunnel.Validate() != nil {
		return ""
	}
	return fmt.Sprintf("[Interface]\nPrivateKey = PRIVATE_KEY_FROM_LOCAL_FILE\nAddress = %s\n\n[Peer]\nPublicKey = %s\nEndpoint = %s\nAllowedIPs = %s\nPersistentKeepalive = 25\n", p.Address, p.Tunnel.GatewayPublicKey, p.Tunnel.Endpoint, p.Tunnel.GatewayAddress)
}

func (m *Manager) EnrollManual(ctx context.Context, actor Actor, id int64, code, publicKey string) (ManualParameters, error) {
	if _, err := m.ManualParameters(ctx, actor, id); err != nil {
		return ManualParameters{}, err
	}
	if err := m.store.manualCode(ctx, id, hash(code), time.Now().Unix()); err != nil {
		return ManualParameters{}, err
	}
	// This browser-independent fallback has no agent bearer to persist locally.
	// Bind retries to the same high-entropy code and public key so an unfinished
	// durable attempt remains recoverable after helper/cleanup failures.
	credential := base64.RawURLEncoding.EncodeToString(hash("sreda/manual/enrollment/" + code + "/" + publicKey))
	if _, err := m.Enroll(ctx, EnrollInput{Code: code, PublicKey: publicKey, Credential: credential}); err != nil {
		return ManualParameters{}, err
	}
	return m.ManualParameters(ctx, actor, id)
}
