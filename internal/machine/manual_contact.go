package machine

import (
	"context"
	"sreda/internal/tunnel"
	"sync"
	"time"
)

const ManualContactLifetime = 180 * time.Second
const contactObservationCache = 30 * time.Second

type contactObservation struct {
	mu        sync.Mutex
	checked   time.Time
	publicKey string
	err       error
}

// ObserveConnection caches the kernel observation for at most30s. The per-machine
// lock never holds the publication or enrollment lock during helper I/O.
func (m *Manager) ObserveConnection(ctx context.Context, id int64) error {
	conn, err := m.store.connection(ctx, id)
	if err != nil {
		return err
	}
	if conn.Mode != ManualMode || !conn.Enabled {
		return nil
	}
	cached, _ := m.contacts.LoadOrStore(id, &contactObservation{})
	observation := cached.(*contactObservation)
	observation.mu.Lock()
	defer observation.mu.Unlock()
	now := m.now()
	if !observation.checked.IsZero() && now.Sub(observation.checked) < contactObservationCache && observation.publicKey == conn.PublicKey {
		return observation.err
	}
	observation.checked = now
	observation.publicKey = conn.PublicKey
	observation.err = failure(Unavailable, "Контакт WireGuard не удалось подтвердить")
	observer, ok := m.gateway.(tunnel.Observer)
	if !ok {
		return observation.err
	}
	bounded, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	latest, err := observer.LatestHandshake(bounded, tunnel.Peer{MachineID: conn.ID, PublicKey: conn.PublicKey, Address: conn.Address})
	if err != nil || latest.After(now.Add(5*time.Second)) {
		return observation.err
	}
	if err = m.store.recordHandshake(bounded, conn, latest); err != nil {
		return observation.err
	}
	observation.err = nil
	return nil
}

// ContactForMode is the shared contact freshness policy. A fresh handshake is
// transport contact only; it is never an application health check.
func ContactForMode(mode Mode, enabled bool, lastSeen, now time.Time) bool {
	lifetime := ContactLifetime
	if mode == ManualMode {
		lifetime = ManualContactLifetime
	}
	return enabled && !lastSeen.IsZero() && !lastSeen.After(now) && now.Sub(lastSeen) < lifetime
}
