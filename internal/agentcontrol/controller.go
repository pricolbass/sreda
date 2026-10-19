// Package agentcontrol coordinates machine credentials and versioned agent routes.
// HTTP encoding and route persistence remain in their respective adapters.
package agentcontrol

import (
	"context"
	"sreda/internal/agentprotocol"
	"sreda/internal/machine"
)

type Acknowledgment = agentprotocol.Acknowledgment
type Heartbeat struct {
	Ready             bool   `json:"ready"`
	AppliedGeneration uint64 `json:"applied_generation,omitempty"`
	FailedGeneration  uint64 `json:"failed_generation,omitempty"`
	ApplyError        string `json:"apply_error,omitempty"`
}

// Routes is the consumer-owned seam to the publication module.
type Routes interface {
	Control(context.Context, int64) (uint64, []agentprotocol.Route, error)
	Acknowledge(context.Context, int64, Acknowledgment) error
}
type Controller struct {
	machines *machine.Manager
	routes   Routes
}

func New(machines *machine.Manager, routes Routes) *Controller {
	return &Controller{machines: machines, routes: routes}
}
func (c *Controller) Enroll(ctx context.Context, input machine.EnrollInput) (agentprotocol.Control, error) {
	conn, err := c.machines.Enroll(ctx, input)
	if err != nil {
		return agentprotocol.Control{}, err
	}
	return c.configuration(ctx, conn)
}
func (c *Controller) Heartbeat(ctx context.Context, credential string, input Heartbeat) (agentprotocol.Control, error) {
	conn, err := c.machines.AuthenticateAgent(ctx, credential)
	if err != nil {
		return agentprotocol.Control{}, err
	}
	if c.routes != nil && input.Ready {
		if err = c.routes.Acknowledge(ctx, conn.ID, Acknowledgment{Applied: input.AppliedGeneration, Failed: input.FailedGeneration, Error: input.ApplyError}); err != nil {
			return agentprotocol.Control{}, err
		}
	}
	if input.Ready {
		if err = c.machines.ObserveContact(ctx, conn.ID); err != nil {
			return agentprotocol.Control{}, err
		}
	}
	return c.configuration(ctx, conn)
}
func (c *Controller) configuration(ctx context.Context, conn machine.Connection) (agentprotocol.Control, error) {
	details, ok := c.machines.GatewayDetails()
	if !ok {
		return agentprotocol.Control{}, &machine.Failure{Kind: machine.Unavailable, Message: "Сетевой шлюз не настроен"}
	}
	control := agentprotocol.Control{MachineID: conn.ID, Address: conn.Address, Tunnel: details, ProxyToken: conn.ProxyToken, Routes: []agentprotocol.Route{}}
	if c.routes != nil {
		generation, routes, err := c.routes.Control(ctx, conn.ID)
		if err != nil {
			return control, err
		}
		control.Generation = generation
		control.Routes = routes
	}
	return control, nil
}
