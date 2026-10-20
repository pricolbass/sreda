package publication

import (
	"errors"
	"net"
	"net/url"
	"sreda/internal/agentprotocol"
	"sreda/internal/machine"
	"strconv"
	"strings"
)

// Transport resolves a registered machine connection to a fixed gateway upstream.
// Agent and manual WireGuard publication use different authenticated upstreams.
// Request data can never choose the endpoint.
type Transport interface {
	Endpoint(Connection) (Endpoint, error)
}
type Connection struct {
	ID                          string
	MachineID                   int64
	Address, ProxyToken, Target string
	Desired, Enabled            bool
	State                       string
	LastSeen                    int64
	Mode                        machine.Mode
}
type Endpoint struct {
	URL             *url.URL
	Headers         map[string]string
	AgentControlled bool
}
type AgentTransport struct{}

func (AgentTransport) Endpoint(c Connection) (Endpoint, error) {
	if err := agentprotocol.ValidateTarget(c.Target); err != nil {
		return Endpoint{}, err
	}
	ip := net.ParseIP(strings.TrimSuffix(c.Address, "/32"))
	if ip == nil || ip.To4() == nil || len(c.ProxyToken) != 43 {
		return Endpoint{}, errors.New("неполная конфигурация подключения")
	}
	return Endpoint{URL: &url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), "9080")}, Headers: map[string]string{"X-Sreda-Publication": c.ID, "X-Sreda-Proxy-Token": c.ProxyToken}, AgentControlled: true}, nil
}

// ManualTransport exposes only the registered port at this machine's assigned
// WireGuard address. Loopback, neighbouring peers and LAN targets are invalid.
type ManualTransport struct{}

func (ManualTransport) Endpoint(c Connection) (Endpoint, error) {
	assigned := net.ParseIP(strings.TrimSuffix(c.Address, "/32"))
	host, port, err := net.SplitHostPort(c.Target)
	number, portErr := strconv.Atoi(port)
	if err != nil || portErr != nil || number < 1 || number > 65535 || assigned == nil || assigned.To4() == nil || host != assigned.String() {
		return Endpoint{}, errors.New("Без агента укажите назначенный IP WireGuard этой машины и порт приложения")
	}
	return Endpoint{URL: &url.URL{Scheme: "http", Host: net.JoinHostPort(assigned.String(), strconv.Itoa(number))}}, nil
}

// ModeTransports is the actual seam between the two delivery adapters.
type ModeTransports map[machine.Mode]Transport

func (t ModeTransports) Endpoint(c Connection) (Endpoint, error) {
	adapter := t[c.Mode]
	if adapter == nil {
		return Endpoint{}, errors.New("неизвестный способ подключения машины")
	}
	return adapter.Endpoint(c)
}
