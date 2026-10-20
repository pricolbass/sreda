// Package access coordinates confirmed user access closure across resource modules.
package access

import (
	"context"
	"errors"
	"sreda/internal/identity"
)

type Accounts interface {
	Block(context.Context, int64, int64, int64) (identity.AccountAccess, error)
	Unblock(context.Context, int64, int64, int64) error
	FinishBlock(context.Context, int64, int64, string) error
}
type Resources interface {
	DisableOwner(context.Context, int64) error
}
type Controller struct {
	accounts               Accounts
	publications, machines Resources
}

func New(a Accounts, p, m Resources) *Controller { return &Controller{a, p, m} }
func (c *Controller) Block(ctx context.Context, actorID, userID, revision int64) error {
	account, err := c.accounts.Block(ctx, actorID, userID, revision)
	if err != nil {
		return err
	}
	closeErr := errors.Join(c.publications.DisableOwner(ctx, userID), c.machines.DisableOwner(ctx, userID))
	problem := ""
	if closeErr != nil {
		problem = closeErr.Error()
	}
	return errors.Join(closeErr, c.accounts.FinishBlock(ctx, userID, account.Revision, problem))
}
func (c *Controller) Unblock(ctx context.Context, actorID, userID, revision int64) error {
	return c.accounts.Unblock(ctx, actorID, userID, revision)
}
