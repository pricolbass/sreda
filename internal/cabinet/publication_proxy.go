package cabinet

import (
	"context"
	"database/sql"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"sync"
	"time"
)

type publicationRoute struct {
	mu             sync.Mutex
	closed         bool
	requests       map[uint64]publicationAdmission
	next           uint64
	connections    map[*publicationConn]bool
	transport      *http.Transport
	proxy          *httputil.ReverseProxy
	drained        chan struct{}
	drainedClosed  bool
	machineID      int64
	address, token string
}
type publicationConn struct {
	net.Conn
	route *publicationRoute
}

func (c *publicationConn) Close() error {
	c.route.mu.Lock()
	delete(c.route.connections, c)
	c.route.mu.Unlock()
	return c.Conn.Close()
}
func (a *App) newPublicationRoute(id string, machineID int64, address, token string) *publicationRoute {
	route := &publicationRoute{requests: map[uint64]publicationAdmission{}, connections: map[*publicationConn]bool{}, machineID: machineID, address: address, token: token}
	route.drained = make(chan struct{})
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dial := a.publications.dial
	if dial == nil {
		dial = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	}
	transport.DialContext = func(ctx context.Context, network, requested string) (net.Conn, error) {
		route.mu.Lock()
		closed := route.closed
		route.mu.Unlock()
		if closed || ctx.Err() != nil {
			return nil, errors.New("публикация отключена")
		}
		conn, err := dial(ctx, network, requested)
		if err != nil {
			return nil, err
		}
		tracked := &publicationConn{Conn: conn, route: route}
		route.mu.Lock()
		defer route.mu.Unlock()
		if route.closed || ctx.Err() != nil {
			conn.Close()
			return nil, errors.New("публикация отключена")
		}
		route.connections[tracked] = true
		return tracked, nil
	}
	route.transport = transport
	route.proxy = httputil.NewSingleHostReverseProxy(&url.URL{Scheme: "http", Host: net.JoinHostPort(strings.TrimSuffix(address, "/32"), "9080")})
	route.proxy.Transport = transport
	route.proxy.Director = nil
	route.proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		originalHost := pr.In.Host
		pr.SetURL(&url.URL{Scheme: "http", Host: net.JoinHostPort(strings.TrimSuffix(address, "/32"), "9080")})
		pr.Out.Host = originalHost
		for header := range pr.Out.Header {
			lower := strings.ToLower(header)
			if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") {
				pr.Out.Header.Del(header)
			}
		}
		pr.Out.Header.Set("X-Forwarded-Proto", "https")
		pr.Out.Header.Set("X-Forwarded-Host", originalHost)
		if clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil && net.ParseIP(clientIP) != nil {
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
		}
		pr.Out.Header.Set("X-Sreda-Publication", id)
		pr.Out.Header.Set("X-Sreda-Proxy-Token", token)
	}
	route.proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Сервис временно недоступен", 503)
	}
	return route
}

type publicationAdmission struct {
	cancel context.CancelFunc
	abort  func()
}

func (r *publicationRoute) admit(ctx context.Context, w http.ResponseWriter) (context.Context, func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ctx, func() {}, false
	}
	ctx, cancel := context.WithCancel(ctx)
	r.next++
	id := r.next
	r.requests[id] = publicationAdmission{cancel: cancel, abort: func() { _ = http.NewResponseController(w).SetWriteDeadline(time.Now()) }}
	return ctx, func() {
		cancel()
		r.mu.Lock()
		delete(r.requests, id)
		if r.closed && len(r.requests) == 0 && !r.drainedClosed {
			close(r.drained)
			r.drainedClosed = true
		}
		r.mu.Unlock()
	}, true
}
func (r *publicationRoute) closeAndWait(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	admissions := make([]publicationAdmission, 0, len(r.requests))
	for _, admission := range r.requests {
		admissions = append(admissions, admission)
	}
	connections := make([]net.Conn, 0, len(r.connections))
	for c := range r.connections {
		connections = append(connections, c)
	}
	if len(r.requests) == 0 && !r.drainedClosed {
		close(r.drained)
		r.drainedClosed = true
	}
	r.mu.Unlock()
	for _, admission := range admissions {
		admission.cancel()
		admission.abort()
	}
	r.transport.CloseIdleConnections()
	for _, c := range connections {
		c.Close()
	}
	select {
	case <-r.drained:
		return nil
	case <-ctx.Done():
		return errors.New("не удалось подтвердить закрытие всех соединений публикации")
	}
}

// closePublicationLocked is the admission barrier for later disable/delete/block.
// Call with a bounded context while holding a.publications.mu after committing desired_enabled=0.
// On failure the cached route remains closed and the operation must stay pending/error.
func (a *App) closePublicationLocked(ctx context.Context, id string) error {
	if route := a.publications.routes[id]; route != nil {
		if err := route.closeAndWait(ctx); err != nil {
			return err
		}
		delete(a.publications.routes, id)
	}
	return nil
}
func (a *App) publicationDispatcher(cabinet http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := strings.ToLower(r.Host)
		if h, port, err := net.SplitHostPort(host); err == nil {
			if port != "443" {
				cabinet.ServeHTTP(w, r)
				return
			}
			host = h
		}
		zone := a.publications.zone
		if host == strings.ToLower(a.host) || zone == "" || !strings.HasSuffix(host, "."+zone) {
			cabinet.ServeHTTP(w, r)
			return
		}
		label := strings.TrimSuffix(host, "."+zone)
		if !subdomainPattern.MatchString(label) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Strict-Transport-Security", "max-age=31536000")
		if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
			http.Error(w, "Требуется HTTPS", 403)
			return
		}
		a.publications.mu.Lock()
		var id, state, address, token string
		var machineID int64
		var last sql.NullInt64
		var desired, enabled bool
		err := a.db.QueryRowContext(r.Context(), `SELECT p.id,p.state,p.desired_enabled,m.id,m.enabled,m.tunnel_address,m.proxy_token,m.last_seen FROM publications p JOIN machines m ON m.id=p.machine_id WHERE p.subdomain=?`, label).Scan(&id, &state, &desired, &machineID, &enabled, &address, &token, &last)
		if errors.Is(err, sql.ErrNoRows) {
			a.publications.mu.Unlock()
			http.NotFound(w, r)
			return
		}
		if err != nil {
			a.publications.mu.Unlock()
			http.Error(w, "Сервис временно недоступен", 503)
			return
		}
		if !desired || !enabled || state != "Настроена" || !last.Valid || time.Since(time.Unix(last.Int64, 0)) >= machineContactLifetime {
			a.publications.mu.Unlock()
			http.Error(w, "Сервис временно недоступен", 503)
			return
		}
		if a.publications.routes == nil {
			a.publications.routes = map[string]*publicationRoute{}
		}
		route := a.publications.routes[id]
		if route == nil {
			route = a.newPublicationRoute(id, machineID, address, token)
			a.publications.routes[id] = route
		}
		ctx, release, ok := route.admit(r.Context(), w)
		a.publications.mu.Unlock()
		if !ok {
			http.Error(w, "Сервис временно недоступен", 503)
			return
		}
		defer release()
		route.proxy.ServeHTTP(w, r.WithContext(ctx))
	})
}
