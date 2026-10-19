// Package tunnel defines the privileged gateway boundary; unavailable means fail closed.
package tunnel

import "context"

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
