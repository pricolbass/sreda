// Package tunnel defines the privileged gateway boundary; unavailable means fail closed.
package tunnel

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net"
	"strconv"
	"strings"
)

type Peer struct {
	MachineID int64  `json:"machine_id"`
	PublicKey string `json:"public_key"`
	Address   string `json:"address"`
}

type Details struct {
	GatewayPublicKey string `json:"gateway_public_key"`
	Endpoint         string `json:"endpoint"`
	GatewayAddress   string `json:"gateway_address"`
}

type Gateway interface {
	Details() Details
	ApplyPeer(context.Context, Peer) error
	RemovePeer(context.Context, Peer) error
}

// Validate rejects configuration that could consume a code but cannot form a tunnel.
func (d Details) Validate() error {
	key, err := base64.StdEncoding.DecodeString(d.GatewayPublicKey)
	if err != nil || len(key) != 32 || base64.StdEncoding.EncodeToString(key) != d.GatewayPublicKey || bytes.Equal(key, make([]byte, 32)) {
		return errors.New("некорректный публичный ключ WireGuard шлюза")
	}
	host, port, err := net.SplitHostPort(d.Endpoint)
	number, portErr := strconv.Atoi(port)
	if err != nil || host == "" || len(host) > 253 || strings.ContainsAny(d.Endpoint, " \r\n\t") || strings.Contains(host, "%") || portErr != nil || number < 1 || number > 65535 {
		return errors.New("некорректный WireGuard endpoint шлюза")
	}
	if d.GatewayAddress != "10.203.0.1/32" {
		return errors.New("неподдерживаемый адрес шлюза")
	}
	return nil
}
