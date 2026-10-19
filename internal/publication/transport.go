package publication

import (
	"errors"
	"net"
	"net/url"
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
}
type Endpoint struct {
	URL     *url.URL
	Headers map[string]string
}
type AgentTransport struct{}

func (AgentTransport) Endpoint(c Connection) (Endpoint, error) {
	ip := net.ParseIP(strings.TrimSuffix(c.Address, "/32"))
	if ip == nil || ip.To4() == nil || len(c.ProxyToken) != 43 {
		return Endpoint{}, errors.New("неполная конфигурация подключения")
	}
	return Endpoint{URL: &url.URL{Scheme: "http", Host: net.JoinHostPort(ip.String(), "9080")}, Headers: map[string]string{"X-Sreda-Publication": c.ID, "X-Sreda-Proxy-Token": c.ProxyToken}}, nil
}
