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
	ConfirmManual(context.Context, agentprotocol.ConnectionIdentity) error
	Control(context.Context, agentprotocol.ConnectionIdentity) (uint64, []agentprotocol.Route, error)
	Acknowledge(context.Context, agentprotocol.ConnectionIdentity, Acknowledgment) error
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
	if conn.Mode == machine.ManualMode {
		if conn.Enabled && c.routes != nil {
			if err := c.routes.ConfirmManual(ctx, conn.Identity()); err != nil {
				return agentprotocol.Control{}, err
			}
		}
		details, _ := c.machines.GatewayDetails()
		return agentprotocol.Control{MachineID: conn.ID, Address: conn.Address, Tunnel: details}, nil
	}
	return c.configuration(ctx, conn)
}
func (c *Controller) Heartbeat(ctx context.Context, credential string, input Heartbeat) (agentprotocol.Control, error) {
	conn, err := c.machines.AuthenticateAgent(ctx, credential)
	if err != nil {
		return agentprotocol.Control{}, err
	}
	if c.routes != nil && input.Ready {
		if err = c.routes.Acknowledge(ctx, conn.Identity(), Acknowledgment{Applied: input.AppliedGeneration, Failed: input.FailedGeneration, Error: input.ApplyError}); err != nil {
			return agentprotocol.Control{}, err
		}
	}
	if input.Ready {
		if err = c.machines.ObserveContact(ctx, conn.Identity()); err != nil {
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
	if c.routes != nil && conn.Enabled {
		generation, routes, err := c.routes.Control(ctx, conn.Identity())
		if err != nil {
			return control, err
		}
		control.Generation = generation
		control.Routes = routes
	}
	return control, nil
}

// EnrollManual applies the same route confirmation as the browser enrollment API.
func (c *Controller) EnrollManual(ctx context.Context, actor machine.Actor, id int64, code, publicKey string) (machine.ManualParameters, error) {
	p, err := c.machines.EnrollManual(ctx, actor, id, code, publicKey)
	if err != nil {
		return p, err
	}
	if p.Enabled && c.routes != nil {
		conn, err := c.machines.Connection(ctx, id)
		if err != nil {
			return p, err
		}
		if err = c.routes.ConfirmManual(ctx, conn.Identity()); err != nil {
			return p, err
		}
	}
	return p, nil
}
func (c *Controller) ChangeAccess(ctx context.Context, actor machine.Actor, id, revision int64, enabled bool) error {
	if err := c.machines.ChangeAccess(ctx, actor, id, revision, enabled); err != nil {
		return err
	}
	if enabled && c.routes != nil {
		conn, err := c.machines.Connection(ctx, id)
		if err != nil {
			return err
		}
		if conn.Mode == machine.ManualMode {
			return c.routes.ConfirmManual(ctx, conn.Identity())
		}
	}
	return nil
}

func (c *Controller) Recover(ctx context.Context, credential, publicKey string) (agentprotocol.Control, error) {
	conn, err := c.machines.RecoverAgent(ctx, credential, publicKey)
	if err != nil {
		return agentprotocol.Control{}, err
	}
	return c.configuration(ctx, conn)
}
