package cabinet_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"sreda/internal/cabinet"
	"sreda/internal/publication"
	"sreda/internal/tunnel"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// This is the external kernel/network boundary. Real Caddy, SQLite, HTTP and
// agent proxies run below; these peers are not actual Linux WireGuard peers.
type readinessGateway struct {
	testGateway
	mu          sync.Mutex
	peers       map[int64]tunnel.Peer
	failRemoval int64
}

func (g *readinessGateway) ApplyPeer(_ context.Context, p tunnel.Peer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.peers[p.MachineID] = p
	return nil
}
func (g *readinessGateway) RemovePeer(_ context.Context, p tunnel.Peer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.failRemoval == p.MachineID {
		return errors.New("injected unconfirmed removal")
	}
	delete(g.peers, p.MachineID)
	return nil
}
func (g *readinessGateway) LatestHandshake(_ context.Context, p tunnel.Peer) (time.Time, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.peers[p.MachineID] != p {
		return time.Time{}, errors.New("peer not applied")
	}
	return time.Now(), nil
}
func (g *readinessGateway) active(address string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	host, _, _ := net.SplitHostPort(address)
	for _, p := range g.peers {
		if strings.TrimSuffix(p.Address, "/32") == host {
			return true
		}
	}
	return false
}
func (g *readinessGateway) fail(id int64) { g.mu.Lock(); g.failRemoval = id; g.mu.Unlock() }

// Existing form helpers send every request through actual TLS/Caddy/Unix here.
func caddyFormBoundary(t *testing.T, client *http.Client) http.Handler {
	t.Helper()
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := r.Clone(r.Context())
		request.RequestURI = ""
		response, err := client.Do(request)
		if err != nil {
			t.Errorf("Caddy form request: %v", err)
			http.Error(w, "local TLS request failed", 502)
			return
		}
		defer response.Body.Close()
		for name, values := range response.Header {
			for _, value := range values {
				w.Header().Add(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	})
}
func formRevision(t *testing.T, b *browser, index, action string) url.Values {
	t.Helper()
	page := b.request("GET", index, nil)
	if page.Code != 200 {
		t.Fatalf("form %s: %d %s", index, page.Code, page.Body.String())
	}
	pattern := regexp.MustCompile(`action="` + regexp.QuoteMeta(action) + `"[^>]*>.*?name="revision" value="([0-9]+)"`)
	match := pattern.FindStringSubmatch(page.Body.String())
	if len(match) != 2 {
		t.Fatalf("missing versioned action %s", action)
	}
	return url.Values{"revision": {match[1]}}
}
func TestLocalReadinessAcrossOwnersAndRestartThroughCaddy(t *testing.T) {
	app, admin, dir := setup(t)
	gateway := &readinessGateway{peers: map[int64]tunnel.Peer{}}
	app.SetGateway(gateway)
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	var current atomic.Pointer[cabinet.App]
	current.Store(app)
	client, _ := caddyClient(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { current.Load().Handler().ServeHTTP(w, r) }))
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	admin.handler = caddyFormBoundary(t, client)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	bob := createOrdinary(t, admin, "bob")
	if signIn(alice, "alice", password) != 303 || signIn(bob, "bob", password) != 303 {
		t.Fatal("invitee login")
	}
	oldSession := *alice.cookies["__Host-sreda-session"]
	var destinations sync.Map
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		target, ok := destinations.Load(address)
		if !ok || !gateway.active(address) {
			return nil, errors.New("logical tunnel unavailable")
		}
		return (&net.Dialer{}).DialContext(ctx, network, target.(string))
	}
	app.SetPublicationDialer(dial)
	create := func(b *browser, name, mode string) (int64, string) {
		t.Helper()
		b.request("GET", "/machines", nil)
		w := b.request("POST", "/machines", url.Values{"name": {name}, "mode": {mode}})
		var result struct {
			ID   int64
			Code string
		}
		if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &result) != nil {
			t.Fatalf("machine: %d %s", w.Code, w.Body.String())
		}
		return result.ID, result.Code
	}
	makeApp := func(marker string) *httptest.Server {
		t.Helper()
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Header.Get("X-Sreda-Publication") != "" || r.Header.Get("X-Sreda-Proxy-Token") != "" {
				t.Error("routing credential reached app")
			}
			io.WriteString(w, marker)
		}))
		t.Cleanup(server.Close)
		return server
	}
	attachAgent := func(state agent.State) *agent.Proxy {
		t.Helper()
		proxy := agent.NewProxy("127.0.0.1")
		t.Cleanup(proxy.Close)
		server := httptest.NewServer(proxy)
		t.Cleanup(server.Close)
		destinations.Store(net.JoinHostPort(strings.TrimSuffix(state.Control.Address, "/32"), "9080"), server.Listener.Addr().String())
		return proxy
	}
	publish := func(b *browser, id int64, label, target string) publication.Publication {
		t.Helper()
		b.request("GET", "/publications", nil)
		w := b.request("POST", "/publications", url.Values{"machine_id": {strconv.FormatInt(id, 10)}, "subdomain": {label}, "target": {target}})
		var p publication.Publication
		if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &p) != nil {
			t.Fatalf("publish: %d %s", w.Code, w.Body.String())
		}
		return p
	}
	acknowledge := func(b *browser, state agent.State, proxy *agent.Proxy) {
		t.Helper()
		response := agentContact(t, b, state.Credential, `{"ready":true}`)
		var control agentprotocol.Control
		if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &control) != nil {
			t.Fatalf("control: %d %s", response.Code, response.Body.String())
		}
		if err := proxy.ApplyControl(control); err != nil {
			t.Fatal(err)
		}
		response = agentContact(t, b, state.Credential, fmt.Sprintf(`{"ready":true,"applied_generation":%d}`, control.Generation))
		if response.Code != 200 {
			t.Fatalf("ack: %d %s", response.Code, response.Body.String())
		}
	}
	check := func(address string, status int, marker string) {
		t.Helper()
		request, _ := http.NewRequest("GET", address, nil)
		request.Header.Set("X-Sreda-Publication", "forged-neighbour")
		request.Header.Set("X-Sreda-Proxy-Token", "forged-secret")
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != status || (marker != "" && string(body) != marker) {
			t.Fatalf("%s: %d %q", address, response.StatusCode, body)
		}
	}
	agentID, code := create(alice, "Alice agent", "agent")
	state, err := agent.Enroll(context.Background(), t.TempDir(), origin, code, client)
	if err != nil {
		t.Fatal(err)
	}
	proxy := attachAgent(state)
	firstApp := makeApp("alice/agent/one")
	secondApp := makeApp("alice/agent/two")
	first := publish(alice, agentID, "application", strings.TrimPrefix(firstApp.URL, "http://"))
	second := publish(alice, agentID, "alice-api", strings.TrimPrefix(secondApp.URL, "http://"))
	acknowledge(alice, state, proxy)
	manualID, manualCode := create(alice, "Alice manual", "manual")
	enrolled := reconnectEnroll(t, alice, manualCode, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("m", 43))
	var manual agentprotocol.Control
	if enrolled.Code != 201 || json.Unmarshal(enrolled.Body.Bytes(), &manual) != nil {
		t.Fatalf("manual enrollment: %d %s", enrolled.Code, enrolled.Body.String())
	}
	manualApp := makeApp("alice/manual")
	manualTarget := net.JoinHostPort(strings.TrimSuffix(manual.Address, "/32"), "8080")
	destinations.Store(manualTarget, manualApp.Listener.Addr().String())
	manualPub := publish(alice, manualID, "alice-manual", manualTarget)
	_, unusedCode := create(alice, "Unused initial code", "agent")
	bobID, bobCode := create(bob, "Bob agent", "agent")
	bobState, err := agent.Enroll(context.Background(), t.TempDir(), origin, bobCode, client)
	if err != nil {
		t.Fatal(err)
	}
	bobProxy := attachAgent(bobState)
	bobApp := makeApp("bob/agent")
	bobPub := publish(bob, bobID, "bob-app", strings.TrimPrefix(bobApp.URL, "http://"))
	acknowledge(bob, bobState, bobProxy)
	check(first.URL, 200, "alice/agent/one")
	check(second.URL, 200, "alice/agent/two")
	check(manualPub.URL, 200, "alice/manual")
	check(bobPub.URL, 200, "bob/agent")
	if w := bob.request("GET", "/publications/"+first.ID, nil); w.Code != 404 {
		t.Fatalf("foreign publication: %d", w.Code)
	}
	if w := alice.request("GET", fmt.Sprintf("/machines/%d", bobID), nil); w.Code != 404 {
		t.Fatalf("foreign machine: %d", w.Code)
	}
	action := fmt.Sprintf("/machines/%d/reconnect", agentID)
	replacement := alice.request("POST", action, formRevision(t, alice, "/machines", action))
	var next struct {
		ID   int64
		Code string
	}
	if replacement.Code != 201 || json.Unmarshal(replacement.Body.Bytes(), &next) != nil || next.ID != agentID {
		t.Fatalf("reconnect: %d %s", replacement.Code, replacement.Body.String())
	}
	if w := agentContact(t, alice, state.Credential, `{"ready":true}`); w.Code != 401 {
		t.Fatalf("old credential: %d", w.Code)
	}
	nextState, err := agent.Enroll(context.Background(), t.TempDir(), origin, next.Code, client)
	if err != nil {
		t.Fatal(err)
	}
	nextProxy := attachAgent(nextState)
	acknowledge(alice, nextState, nextProxy)
	check(first.URL, 200, "alice/agent/one")
	check(second.URL, 200, "alice/agent/two")
	if retained := publicationDetail(t, alice, first.ID); retained.URL != first.URL {
		t.Fatal("reconnect lost URL")
	}
	gateway.fail(agentID)
	blockPath := "/admin/users/2/block"
	if w := admin.request("POST", blockPath, formRevision(t, admin, "/admin/users", blockPath)); w.Code != 503 {
		t.Fatalf("unconfirmed block: %d %s", w.Code, w.Body.String())
	}
		check(first.URL, 404, "")
		check(manualPub.URL, 404, "")
	check(bobPub.URL, 200, "bob/agent")
	if w := alice.request("GET", "/", nil); w.Code != 303 {
		t.Fatalf("old session: %d", w.Code)
	}
	if signIn(alice, "alice", password) != 401 {
		t.Fatal("blocked login accepted")
	}
	if w := reconnectEnroll(t, alice, unusedCode, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("u", 43)); w.Code != 401 {
		t.Fatalf("old initial code: %d", w.Code)
	}
	page := admin.request("GET", "/admin/users", nil)
	if !strings.Contains(page.Body.String(), "Ошибка закрытия доступа") || strings.Contains(page.Body.String(), "<p>Доступ закрыт</p>") {
		t.Fatal("unconfirmed block reported closed")
	}
	// Reopen application/SQLite while the same actual Caddy keeps its Unix backend.
	// True child-process and Caddy restarts are separate production-CLI tests.
	if err = app.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	reopened.SetGateway(gateway)
	reopened.SetPublicationDialer(dial)
	current.Store(reopened)
	gateway.fail(0)
	if err = reopened.ReconcileMachinePeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	page = admin.request("GET", "/admin/users", nil)
	if !strings.Contains(page.Body.String(), "<p>Доступ закрыт</p>") {
		t.Fatal("persisted block did not resume")
	}
		check(first.URL, 404, "")
		check(manualPub.URL, 404, "")
	check(bobPub.URL, 200, "bob/agent")
	unblockPath := "/admin/users/2/unblock"
	if w := admin.request("POST", unblockPath, formRevision(t, admin, "/admin/users", unblockPath)); w.Code != 303 {
		t.Fatalf("unblock: %d %s", w.Code, w.Body.String())
	}
	alice.cookies[oldSession.Name] = &oldSession
	if w := alice.request("GET", "/", nil); w.Code != 303 {
		t.Fatal("old session resurrected")
	}
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("new login refused")
	}
	check(first.URL, 503, "")
	check(manualPub.URL, 503, "")
	enablePath := fmt.Sprintf("/machines/%d/enable", agentID)
	if w := alice.request("POST", enablePath, formRevision(t, alice, "/machines", enablePath)); w.Code != 303 {
		t.Fatalf("machine enable: %d %s", w.Code, w.Body.String())
	}
	if p := publicationDetail(t, alice, first.ID); p.DesiredEnabled {
		t.Fatal("machine enable restored publication")
	}
	p := publicationDetail(t, alice, first.ID)
	if w := alice.request("POST", "/publications/"+p.ID+"/enable", url.Values{"revision": {strconv.FormatInt(p.Revision, 10)}}); w.Code != 303 {
		t.Fatalf("publication enable: %d %s", w.Code, w.Body.String())
	}
	acknowledge(alice, nextState, nextProxy)
	check(first.URL, 200, "alice/agent/one")
	check(second.URL, 503, "")
	check(manualPub.URL, 503, "")
	check(bobPub.URL, 200, "bob/agent")
}
