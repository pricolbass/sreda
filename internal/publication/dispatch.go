package publication

import (
	"net"
	"net/http"
	"strings"
	"time"
)

// Wrap dispatches only configured-zone HTTPS hosts; cabinet requests retain their
// separate authentication, CSRF and response policies. Forwarding admission and
// future lifecycle closure share m.mu, so stale reads cannot recreate access.
func (m *Module) Wrap(cabinet http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, port, err := net.SplitHostPort(host); err == nil {
			if port != "443" {
				cabinet.ServeHTTP(w, r)
				return
			}
			host = h
		}
		if host == strings.ToLower(m.cabinetHost) || m.zone == "" || !strings.HasSuffix(host, "."+m.zone) {
			cabinet.ServeHTTP(w, r)
			return
		}
		label := strings.TrimSuffix(host, "."+m.zone)
		if !subdomainPattern.MatchString(label) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Error(w, "Требуется HTTPS", 403)
			return
		}
		m.mu.Lock()
		connection, err := m.store.connection(r.Context(), label)
		if err != nil {
			m.mu.Unlock()
			if domainErr, ok := err.(*Error); ok && domainErr.Kind == NotFound {
				http.NotFound(w, r)
			} else {
				http.Error(w, "Сервис временно недоступен", 503)
			}
			return
		}
		if !connection.Desired || !connection.Enabled || connection.State != "Настроена" || connection.LastSeen == 0 || time.Since(time.Unix(connection.LastSeen, 0)) >= 90*time.Second {
			m.mu.Unlock()
			http.Error(w, "Сервис временно недоступен", 503)
			return
		}
		endpoint, err := m.transport.Endpoint(connection)
		if err != nil {
			m.mu.Unlock()
			http.Error(w, "Сервис временно недоступен", 503)
			return
		}
		route := m.forwarder.routes[connection.ID]
		if route == nil {
			route = m.forwarder.newRoute(connection.ID, endpoint)
			m.forwarder.routes[connection.ID] = route
		}
		ctx, release, ok := route.admit(r.Context(), w)
		m.mu.Unlock()
		if !ok {
			http.Error(w, "Сервис временно недоступен", 503)
			return
		}
		defer release()
		route.proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}
