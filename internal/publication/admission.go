package publication

import (
	"context"
	"sreda/internal/machine"
	"time"
)

type admittedPublication struct {
	route   *publicationRoute
	ctx     context.Context
	release func()
}

// resolveAndAdmit shares serialization with access changes. No caller can use a
// persisted snapshot to recreate a route after a later disable has committed.
func (m *Module) resolveAndAdmit(ctx context.Context, label string, abort func()) (admittedPublication, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	connection, err := m.store.connection(ctx, label)
	if err != nil {
		return admittedPublication{}, err
	}
	if !connection.Desired || connection.State != "Настроена" || !machine.ContactIsOnline(connection.Enabled, time.Unix(connection.LastSeen, 0), time.Now()) {
		return admittedPublication{}, fail(Unavailable, "Сервис временно недоступен")
	}
	endpoint, err := m.transport.Endpoint(connection)
	if err != nil {
		return admittedPublication{}, fail(Unavailable, "Сервис временно недоступен")
	}
	route := m.forwarder.routes[connection.ID]
	if route == nil {
		route = m.forwarder.newRoute(connection.ID, endpoint)
		m.forwarder.routes[connection.ID] = route
	}
	requestCtx, release, ok := route.admit(ctx, abort)
	if !ok {
		return admittedPublication{}, fail(Unavailable, "Сервис временно недоступен")
	}
	return admittedPublication{route: route, ctx: requestCtx, release: release}, nil
}
