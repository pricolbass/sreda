package publication

import (
	"context"
	"time"
)

// Route capture and eviction require m.mu; draining always happens without it.
// Failed drains retain the closed route so later cleanup can confirm closure.
func (m *Module) stopRouteLocked(id string) *publicationRoute {
	route := m.forwarder.routes[id]
	if route != nil {
		route.stopAdmission()
	}
	return route
}

func (m *Module) stopRoutesLocked(pubs []Publication) map[string]*publicationRoute {
	routes := make(map[string]*publicationRoute)
	for _, p := range pubs {
		if route := m.stopRouteLocked(p.ID); route != nil {
			routes[p.ID] = route
		}
	}
	return routes
}

// Start every cancellation before any wait can exhaust the caller's budget.
func cancelRoutes(routes map[string]*publicationRoute) {
	for _, route := range routes {
		route.cancelActive()
	}
}

func drainRoute(ctx context.Context, route *publicationRoute, budget time.Duration) error {
	closeCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	if route == nil {
		return nil
	}
	return route.closeAndWait(closeCtx)
}

func (m *Module) evictDrainedRouteLocked(id string, route *publicationRoute, closeErr error) {
	if closeErr == nil && m.forwarder.routes[id] == route {
		delete(m.forwarder.routes, id)
	}
}
