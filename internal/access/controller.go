// Package access coordinates confirmed user access closure across resource modules.
package access

import (
	"context"
	"errors"
	"sreda/internal/identity"
	"time"
)

type Accounts interface {
	Block(context.Context, int64, int64, int64) (identity.AccountAccess, error)
	Unblock(context.Context, int64, int64, int64) error
	FinishBlock(context.Context, int64, int64, string, string) error
	PendingClosures(context.Context) ([]identity.AccountAccess, error)
	ClaimClosure(context.Context, int64, int64) (string, error)
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
	return c.closeAccount(ctx, account)
}
func (c *Controller) closeAccount(ctx context.Context, account identity.AccountAccess) error {
	lease, err := c.accounts.ClaimClosure(ctx, account.ID, account.Revision)
	if err != nil || lease == "" {
		return err
	}
	// A durable lease outlives both bounded resource phases. Another process may
	// resume a crashed worker only after its network operations must have ended.
	pubCtx, stop := context.WithTimeout(ctx, 30*time.Second)
	pubErr := c.publications.DisableOwner(pubCtx, account.ID)
	stop()
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	closeErr := errors.Join(pubErr, c.machines.DisableOwner(cleanupCtx, account.ID))
	problem := ""
	if closeErr != nil {
		problem = closeErr.Error()
	}
	persistCtx, persistCancel := context.WithTimeout(context.WithoutCancel(ctx), 3*time.Second)
	defer persistCancel()
	return errors.Join(closeErr, c.accounts.FinishBlock(persistCtx, account.ID, account.Revision, lease, problem))
}

// Resume continues persisted incomplete closures without replaying a human command.
func (c *Controller) Resume(ctx context.Context) error {
	pending, err := c.accounts.PendingClosures(ctx)
	if err != nil {
		return err
	}
	var failures []error
	for _, account := range pending {
		if ctx.Err() != nil {
			failures = append(failures, ctx.Err())
			break
		}
		failures = append(failures, c.closeAccount(ctx, account))
	}
	return errors.Join(failures...)
}
func (c *Controller) Unblock(ctx context.Context, actorID, userID, revision int64) error {
	return c.accounts.Unblock(ctx, actorID, userID, revision)
}
