package machine

import "context"

// SetupParameters deliberately contains no credentials or enrollment codes.
// Even administrators can request setup instructions only for their own machine.
type SetupParameters struct {
	ID      int64
	Name    string
	Mode    Mode
	Address string
}

func (m *Manager) SetupParameters(ctx context.Context, ownerID, id int64) (SetupParameters, error) {
	return m.store.setupParameters(ctx, ownerID, id)
}
