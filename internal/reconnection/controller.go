// Package reconnection coordinates connection replacement and gateway draining.
package reconnection

import (
	"context"
	"sreda/internal/machine"
	"time"
)

type Machines interface {
	PrepareReconnect(context.Context, machine.Actor, int64, int64) (machine.Reconnection, error)
	CompleteReconnect(context.Context, machine.Reconnection) (machine.Enrollment, error)
	ReconnectFailed(context.Context, machine.Reconnection, string) error
}
type Publications interface {
	SuspendMachine(context.Context, int64, int64, int64) error
}
type Controller struct {
	machines     Machines
	publications Publications
}

func New(m Machines, p Publications) *Controller { return &Controller{m, p} }
func (c *Controller) Replace(ctx context.Context, actor machine.Actor, id, revision int64) (machine.Enrollment, error) {
	r, err := c.machines.PrepareReconnect(ctx, actor, id, revision)
	if err != nil {
		return machine.Enrollment{}, err
	}
	if err = c.publications.SuspendMachine(ctx, r.MachineID(), r.Revision(), r.OwnerRevision()); err == nil {
		var e machine.Enrollment
		e, err = c.machines.CompleteReconnect(ctx, r)
		if err == nil {
			return e, nil
		}
	}
	persist, cancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer cancel()
	_ = c.machines.ReconnectFailed(persist, r, err.Error())
	return machine.Enrollment{}, err
}
