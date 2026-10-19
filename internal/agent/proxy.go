// Package agent implements the machine-side control client and publication proxy.
package agent

import (
	"context"
	"crypto/subtle"
	"errors"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"reflect"
	"sreda/internal/agentprotocol"
	"sync"
)

// Proxy accepts only registered publications from the gateway's private tunnel address.
// The caller must bind its HTTP server to the agent's exact WireGuard address.
type Proxy struct {
	mu          sync.RWMutex
	gatewayIP   string
	control     agentprotocol.Control
	initialized bool
	suspended   bool
	routes      map[string]*proxyRoute
}
type proxyRoute struct {
	target      string
	proxy       *httputil.ReverseProxy
	mu          sync.Mutex
	closed      bool
	connections map[*routeConn]bool
	transport   *http.Transport
}
type routeConn struct {
	net.Conn
	route *proxyRoute
}

func (c *routeConn) Close() error {
	c.route.mu.Lock()
	delete(c.route.connections, c)
	c.route.mu.Unlock()
	return c.Conn.Close()
}
func NewProxy(gatewayIP string) *Proxy {
	return &Proxy{gatewayIP: gatewayIP, routes: make(map[string]*proxyRoute)}
}

// ValidateTargetSyntax validates literal endpoints without assuming this host owns the IP.
func ValidateTargetSyntax(target string) error { return agentprotocol.ValidateTarget(target) }

// ValidateTarget additionally requires ownership by this agent's machine.
func ValidateTarget(target string) error {
	if err := ValidateTargetSyntax(target); err != nil {
		return err
	}
	host, _, _ := net.SplitHostPort(target)
	ip := net.ParseIP(host)
	if ip.IsLoopback() {
		return nil
	}
	addresses, err := net.InterfaceAddrs()
	if err != nil {
		return errors.New("не удалось проверить адреса машины")
	}
	for _, address := range addresses {
		own, _, err := net.ParseCIDR(address.String())
		if err == nil && own.Equal(ip) {
			return nil
		}
	}
	return errors.New("адрес не принадлежит интерфейсам этой машины")
}
func newRoute(target string) *proxyRoute {
	route := &proxyRoute{target: target, connections: make(map[*routeConn]bool)}
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, network, address)
		if err != nil {
			return nil, err
		}
		tracked := &routeConn{Conn: conn, route: route}
		route.mu.Lock()
		defer route.mu.Unlock()
		if route.closed {
			conn.Close()
			return nil, errors.New("публикация отключена")
		}
		route.connections[tracked] = true
		return tracked, nil
	}
	route.transport = transport
	upstream := &url.URL{Scheme: "http", Host: target}
	route.proxy = httputil.NewSingleHostReverseProxy(upstream)
	route.proxy.Transport = transport
	director := route.proxy.Director
	route.proxy.Director = func(r *http.Request) {
		director(r)
		r.Header.Del("X-Sreda-Proxy-Token")
		r.Header.Del("X-Sreda-Publication")
	}
	route.proxy.ErrorHandler = func(w http.ResponseWriter, _ *http.Request, _ error) {
		http.Error(w, "Сервис временно недоступен", 503)
	}
	return route
}
func (r *proxyRoute) close() {
	r.mu.Lock()
	r.closed = true
	connections := make([]net.Conn, 0, len(r.connections))
	for c := range r.connections {
		connections = append(connections, c)
	}
	r.mu.Unlock()
	r.transport.CloseIdleConnections()
	for _, c := range connections {
		c.Close()
	}
}

// ApplyControl replaces the registered map only when the complete update is valid.
// Closing removed routes also closes active HTTP/WebSocket upstream connections.
func (p *Proxy) ApplyControl(c agentprotocol.Control) error {
	if len(c.ProxyToken) != 43 {
		return errors.New("неверная учётная запись шлюза")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.initialized && c.Generation < p.control.Generation {
		return errors.New("устаревшая версия маршрутов")
	}
	if p.initialized && c.Generation == p.control.Generation {
		if !reflect.DeepEqual(c, p.control) {
			return errors.New("версия маршрутов не изменилась")
		}
		if !p.suspended {
			return nil
		}
	}
	seen := map[string]bool{}
	for _, r := range c.Routes {
		if r.ID == "" || len(r.ID) > 100 || seen[r.ID] {
			return errors.New("некорректный идентификатор публикации")
		}
		seen[r.ID] = true
		if r.Enabled {
			if err := ValidateTarget(r.Target); err != nil {
				return err
			}
		}
	}
	next := map[string]*proxyRoute{}
	for _, r := range c.Routes {
		if !r.Enabled {
			continue
		}
		if old := p.routes[r.ID]; old != nil && old.target == r.Target {
			next[r.ID] = old
		} else {
			next[r.ID] = newRoute(r.Target)
		}
	}
	for id, r := range p.routes {
		if next[id] != r {
			r.close()
		}
	}
	p.routes = next
	c.Routes = append([]agentprotocol.Route(nil), c.Routes...)
	p.control = c
	p.suspended = false
	p.initialized = true
	return nil
}
func (p *Proxy) Close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, r := range p.routes {
		r.close()
	}
	p.routes = map[string]*proxyRoute{}
	p.suspended = true
}
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	remote, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil || remote != p.gatewayIP {
		http.Error(w, "Доступ запрещён", 403)
		return
	}
	p.mu.RLock()
	token := p.control.ProxyToken
	route := p.routes[r.Header.Get("X-Sreda-Publication")]
	authorized := p.initialized && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Sreda-Proxy-Token")), []byte(token)) == 1
	p.mu.RUnlock()
	if !authorized {
		http.Error(w, "Доступ запрещён", 403)
		return
	}
	if route == nil {
		http.NotFound(w, r)
		return
	}
	route.proxy.ServeHTTP(w, r)
}
