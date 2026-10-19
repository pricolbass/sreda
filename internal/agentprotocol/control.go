// Package agentprotocol contains the HTTPS control protocol shared by gateway and agent.
package agentprotocol

import "sreda/internal/tunnel"

type Route struct {
	ID      string `json:"id"`
	Target  string `json:"target"`
	Enabled bool   `json:"enabled"`
}
type Control struct {
	MachineID  int64          `json:"machine_id"`
	Address    string         `json:"address"`
	Tunnel     tunnel.Details `json:"tunnel"`
	ProxyToken string         `json:"proxy_token,omitempty"`
	Generation uint64         `json:"generation"`
	Routes     []Route        `json:"routes"`
}

// Acknowledgment reports only the snapshot actually applied by the machine.
type Acknowledgment struct {
	Applied uint64
	Failed  uint64
	Error   string
}
