package publication

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"strings"
	"sync"
	"time"
)

type forwarder struct {
	routes map[string]*publicationRoute
	dial   func(context.Context, string, string) (net.Conn, error)
}

func newForwarder() *forwarder { return &forwarder{routes: map[string]*publicationRoute{}} }

// close leaves a failed route closed for a later cleanup retry.
func (f *forwarder) close(ctx context.Context, id string) error {
	if route := f.routes[id]; route != nil {
		if err := route.closeAndWait(ctx); err != nil {
			return err
		}
		delete(f.routes, id)
	}
	return nil
}

type publicationRoute struct {
	mu            sync.Mutex
	closed        bool
	requests      map[uint64]publicationAdmission
	next          uint64
	connections   map[*publicationConn]bool
	transport     *http.Transport
	proxy         *httputil.ReverseProxy
	drained       chan struct{}
	drainedClosed bool
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
func (f *forwarder) newRoute(id string, endpoint Endpoint) *publicationRoute {
	route := &publicationRoute{requests: map[uint64]publicationAdmission{}, connections: map[*publicationConn]bool{}}
	route.drained = make(chan struct{})
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	dial := f.dial
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
	route.proxy = httputil.NewSingleHostReverseProxy(endpoint.URL)
	route.proxy.Transport = transport
	route.proxy.Director = nil
	route.proxy.Rewrite = func(pr *httputil.ProxyRequest) {
		originalHost := pr.In.Host
		pr.SetURL(endpoint.URL)
		pr.Out.Host = originalHost
		for header := range pr.Out.Header {
			lower := strings.ToLower(header)
			if lower == "forwarded" || strings.HasPrefix(lower, "x-forwarded-") || lower == "x-sreda-proxy-token" || lower == "x-sreda-publication" {
				pr.Out.Header.Del(header)
			}
		}
		pr.Out.Header.Set("X-Forwarded-Proto", "https")
		pr.Out.Header.Set("X-Forwarded-Host", originalHost)
		if clientIP, _, err := net.SplitHostPort(pr.In.RemoteAddr); err == nil && net.ParseIP(clientIP) != nil {
			pr.Out.Header.Set("X-Forwarded-For", clientIP)
		}
		for key, value := range endpoint.Headers {
			pr.Out.Header.Set(key, value)
		}
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

func (r *publicationRoute) admit(ctx context.Context, abort func()) (context.Context, func(), bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return ctx, func() {}, false
	}
	ctx, cancel := context.WithCancel(ctx)
	r.next++
	id := r.next
	r.requests[id] = publicationAdmission{cancel: cancel, abort: abort}
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

// stopAdmission is quick and runs under the module lifecycle lock; draining is outside it.
func (r *publicationRoute) stopAdmission() { r.mu.Lock(); r.closed = true; r.mu.Unlock() }

func (r *publicationRoute) cancelActive() {
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
}
func (r *publicationRoute) closeAndWait(ctx context.Context) error {
	r.cancelActive()
	select {
	case <-r.drained:
		return nil
	case <-ctx.Done():
		return errors.New("не удалось подтвердить закрытие всех соединений публикации")
	}
}
