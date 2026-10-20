package cabinet_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func reconnectEnroll(t *testing.T, b *browser, code, key, credential string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+code+`","public_key":"`+key+`","credential":"`+credential+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	return w
}
func TestReconnectReplacesCredentialsAndRetainsExistingPublications(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	old := enrolledMachine(t, b)
	p := lifecyclePublication(t, b, "retained", "127.0.0.1:8080")
	if w := agentContact(t, b, old, `{"ready":true,"applied_generation":1}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	b.request("GET", "/machines", nil)
	response := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}})
	if response.Code != 201 {
		t.Fatalf("reconnect %d %s", response.Code, response.Body.String())
	}
	var next struct {
		ID        int64  `json:"id"`
		Code      string `json:"code"`
		ExpiresAt int64  `json:"expires_at"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &next); err != nil {
		t.Fatal(err)
	}
	if next.ExpiresAt < time.Now().Add(14*time.Minute).Unix() || next.ExpiresAt > time.Now().Add(15*time.Minute).Unix() {
		t.Fatal("replacement code lifetime differs from15minutes")
	}
	if next.ID != 1 || len(next.Code) != 43 {
		t.Fatalf("different machine: %s", response.Body.String())
	}
	if w := agentContact(t, b, old, `{"ready":true,"applied_generation":1}`); w.Code != 401 {
		t.Fatalf("old credentials accepted %d", w.Code)
	}
	credential := strings.Repeat("n", 43)
	enrolled := reconnectEnroll(t, b, next.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", credential)
	if enrolled.Code != 201 {
		t.Fatalf("new agent %d %s", enrolled.Code, enrolled.Body.String())
	}
	var control struct {
		MachineID  int64  `json:"machine_id"`
		Generation uint64 `json:"generation"`
		Routes     []struct {
			ID, Target string
			Enabled    bool
		}
	}
	if err := json.Unmarshal(enrolled.Body.Bytes(), &control); err != nil {
		t.Fatal(err)
	}
	if control.MachineID != 1 || len(control.Routes) != 1 || control.Routes[0].ID != p.ID || !control.Routes[0].Enabled || control.Routes[0].Target != "127.0.0.1:8080" {
		t.Fatalf("lost publication: %s", enrolled.Body.String())
	}
	if q := publicationDetail(t, b, p.ID); q.URL != p.URL || !q.DesiredEnabled || q.State != "Настраивается" {
		t.Fatalf("lost settings: %+v", q)
	}
	if replay := reconnectEnroll(t, b, next.Code, "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("r", 43)); replay.Code != 401 {
		t.Fatalf("code reused %d", replay.Code)
	}
}

func TestReconnectDoesNotEnableDisabledConnectionOrPublication(t *testing.T) {
	app, b, dir := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	old := enrolledMachine(t, b)
	p := lifecyclePublication(t, b, "off-retained", "127.0.0.1:8080")
	agentContact(t, b, old, `{"ready":true,"applied_generation":1}`)
	if w := b.request("POST", "/publications/"+p.ID+"/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	b.request("GET", "/machines", nil)
	if w := b.request("POST", "/machines/1/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	response := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"2"}})
	if response.Code != 201 {
		t.Fatal(response.Code, response.Body.String())
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetGateway(testGateway{})
	b.handler = reopened.Handler()
	var next struct{ Code string }
	json.Unmarshal(response.Body.Bytes(), &next)
	credential := strings.Repeat("n", 43)
	w := reconnectEnroll(t, b, next.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", credential)
	if w.Code != 201 {
		t.Fatalf("off enrollment cannot finish client state: %d %s", w.Code, w.Body.String())
	}
	var control struct {
		Address string
		Routes  []any
	}
	json.Unmarshal(w.Body.Bytes(), &control)
	if len(control.Routes) != 0 || control.Address != "10.203.0.2/32" {
		t.Fatalf("off enrollment must return only retained tunnel metadata: %s", w.Body.String())
	}
	if w := agentContact(t, b, credential, `{"ready":true}`); w.Code != 401 {
		t.Fatalf("replacement re-enabled intentionally disabled connection: %d", w.Code)
	}
	if q := publicationDetail(t, b, p.ID); q.DesiredEnabled || q.State != "Отключена" {
		t.Fatalf("publication revived %+v", q)
	}
	b.request("GET", "/machines", nil)
	if w := b.request("POST", "/machines/1/enable", url.Values{"revision": {"3"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := agentContact(t, b, credential, `{"ready":true}`); w.Code != 200 {
		t.Fatalf("new agent cannot resume after explicit enable %d %s", w.Code, w.Body.String())
	}
}

func TestReconnectRemovalFailureSurvivesRestartWithoutIssuingCode(t *testing.T) {
	app, b, dir := setup(t)
	gateway := &removalGateway{}
	app.SetGateway(gateway)
	b.login()
	old := enrolledMachine(t, b)
	gateway.fail.Store(true)
	b.request("GET", "/machines", nil)
	w := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}})
	if w.Code != 503 || strings.Contains(w.Body.String(), `"code"`) {
		t.Fatalf("unconfirmed replacement issued code %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, b, old, `{"ready":false}`); w.Code != 401 {
		t.Fatal("old credential survived durable intent")
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetGateway(gateway)
	b.handler = reopened.Handler()
	if page := b.request("GET", "/machines", nil); !strings.Contains(page.Body.String(), "Ошибка переподключения") {
		t.Fatal("replacement error lost at restart")
	}
	gateway.fail.Store(false)
	w = b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"2"}})
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var next struct{ Code string }
	json.Unmarshal(w.Body.Bytes(), &next)
	if w := reconnectEnroll(t, b, next.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("n", 43)); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
}

func TestReconnectManualModeKeepsTunnelAddressAndPublicationTarget(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	b.request("GET", "/machines", nil)
	c := b.request("POST", "/machines", url.Values{"name": {"Manual machine"}, "mode": {"manual"}})
	var created struct{ Code string }
	json.Unmarshal(c.Body.Bytes(), &created)
	if w := reconnectEnroll(t, b, created.Code, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("m", 43)); w.Code != 201 {
		t.Fatal(w.Code)
	}
	b.request("GET", "/publications", nil)
	p := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"manual-retained"}, "target": {"10.203.0.2:8080"}})
	if p.Code != 201 {
		t.Fatal(p.Code, p.Body.String())
	}
	b.request("GET", "/machines", nil)
	r := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}})
	if r.Code != 201 {
		t.Fatal(r.Code, r.Body.String())
	}
	var next struct{ Code string }
	json.Unmarshal(r.Body.Bytes(), &next)
	w := b.request("POST", "/machines/1/wireguard", url.Values{"code": {next.Code}, "public_key": {"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}})
	if w.Code != 201 || !strings.Contains(w.Body.String(), "10.203.0.2/32") {
		t.Fatalf("manual replacement unusable %d %s", w.Code, w.Body.String())
	}
	var publication struct{ ID string }
	json.Unmarshal(p.Body.Bytes(), &publication)
	if current := publicationDetail(t, b, publication.ID); current.State != "Настроена" || current.Target != "10.203.0.2:8080" {
		t.Fatalf("manual publication did not resume %+v", current)
	}
	if w := reconnectEnroll(t, b, created.Code, "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("r", 43)); w.Code != 401 {
		t.Fatal("original code revived")
	}
}

type pausedReconnectDetails struct {
	testGateway
	pause            atomic.Bool
	entered, release chan struct{}
}

func (g *pausedReconnectDetails) Details() tunnel.Details {
	if g.pause.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
	}
	return g.testGateway.Details()
}
func TestReconnectRejectsAlreadyAuthenticatedOldControlSnapshot(t *testing.T) {
	app, b, _ := setup(t)
	g := &pausedReconnectDetails{entered: make(chan struct{}), release: make(chan struct{})}
	app.SetGateway(g)
	b.login()
	old := enrolledMachine(t, b)
	g.pause.Store(true)
	oldDone := make(chan *httptest.ResponseRecorder, 1)
	go func() { oldDone <- agentContact(t, b, old, `{"ready":false}`) }()
	select {
	case <-g.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("old control did not reach external helper details")
	}
	b.request("GET", "/machines", nil)
	w := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}})
	if w.Code != 201 {
		close(g.release)
		t.Fatal(w.Code, w.Body.String())
	}
	var next struct{ Code string }
	json.Unmarshal(w.Body.Bytes(), &next)
	w = reconnectEnroll(t, b, next.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("n", 43))
	if w.Code != 201 {
		close(g.release)
		t.Fatal(w.Code, w.Body.String())
	}
	close(g.release)
	select {
	case response := <-oldDone:
		if response.Code == 200 || strings.Contains(response.Body.String(), "proxy_token") {
			t.Fatalf("old auth snapshot received current control %d %s", response.Code, response.Body.String())
		}
	case <-time.After(time.Second):
		t.Fatal("old heartbeat hung")
	}
}

func TestReconnectReplacesCachedProxyTokenForRetainedPublication(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	credential := enrolledMachine(t, b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "retained application") }))
	defer upstream.Close()
	proxy := agent.NewProxy("127.0.0.1")
	defer proxy.Close()
	agentServer := httptest.NewServer(proxy)
	defer agentServer.Close()
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, agentServer.Listener.Addr().String())
	})
	p := lifecyclePublication(t, b, "cached-reconnect", strings.TrimPrefix(upstream.URL, "http://"))
	apply := func(credential string, generation uint64) {
		t.Helper()
		var control agentprotocol.Control
		response := agentContact(t, b, credential, `{"ready":false}`)
		if response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
		if err := json.Unmarshal(response.Body.Bytes(), &control); err != nil {
			t.Fatal(err)
		}
		if err := proxy.ApplyControl(control); err != nil {
			t.Fatal(err)
		}
		response = agentContact(t, b, credential, fmt.Sprintf(`{"ready":true,"applied_generation":%d}`, generation))
		if response.Code != 200 {
			t.Fatal(response.Code, response.Body.String())
		}
	}
	apply(credential, 1)
	server := httptest.NewTLSServer(app.Handler())
	defer server.Close()
	client := server.Client()
	client.Timeout = 3 * time.Second
	check := func() {
		t.Helper()
		request, _ := http.NewRequest("GET", server.URL, nil)
		request.Host = "cached-reconnect.example.test"
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != 200 || string(body) != "retained application" {
			t.Fatalf("retained publication uses revoked proxy endpoint: %d %s", response.StatusCode, body)
		}
	}
	check() // Creates the gateway's cached endpoint with the old proxy token.
	b.request("GET", "/machines", nil)
	response := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}})
	if response.Code != 201 {
		t.Fatal(response.Code, response.Body.String())
	}
	var next struct{ Code string }
	json.Unmarshal(response.Body.Bytes(), &next)
	credential = strings.Repeat("n", 43)
	response = reconnectEnroll(t, b, next.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", credential)
	if response.Code != 201 {
		t.Fatal(response.Code, response.Body.String())
	}
	var enrolled agentprotocol.Control
	json.Unmarshal(response.Body.Bytes(), &enrolled)
	apply(credential, enrolled.Generation)
	check()
	if current := publicationDetail(t, b, p.ID); current.URL != p.URL {
		t.Fatal("changed publication address")
	}
}

func TestReconnectWaitsForLiveEnrollmentAndRejectsItsLatePromotion(t *testing.T) {
	app, b, dir := setup(t)
	g := &heldEnrollmentGateway{entered: make(chan struct{}, 1), release: make(chan struct{})}
	app.SetGateway(g)
	b.login()
	code := createEnrollmentCode(t, b, "Live enrollment")
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetGateway(g)
	other := *b
	other.handler = second.Handler()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- reconnectEnroll(t, b, code, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("o", 43))
	}()
	select {
	case <-g.entered:
	case <-time.After(time.Second):
		t.Fatal("enrollment did not reach helper")
	}
	other.request("GET", "/machines", nil)
	w := other.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}})
	if w.Code != 503 || strings.Contains(w.Body.String(), `"code"`) {
		close(g.release)
		t.Fatalf("code exposed before old apply settled %d %s", w.Code, w.Body.String())
	}
	close(g.release)
	if response := <-done; response.Code == 201 {
		t.Fatal("old enrollment promoted after replacement intent")
	}
	if response := agentContact(t, &other, strings.Repeat("o", 43), `{"ready":false}`); response.Code != 401 {
		t.Fatal("unfinished old credential became active")
	}
	w = other.request("POST", "/machines/1/reconnect", url.Values{"revision": {"2"}})
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	var next struct{ Code string }
	json.Unmarshal(w.Body.Bytes(), &next)
	if w := reconnectEnroll(t, &other, next.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("n", 43)); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
}

type pausedReconnectRemoval struct {
	testGateway
	pause            atomic.Bool
	entered, release chan struct{}
}

func (g *pausedReconnectRemoval) RemovePeer(context.Context, tunnel.Peer) error {
	if g.pause.CompareAndSwap(true, false) {
		close(g.entered)
		<-g.release
	}
	return nil
}
func TestReconnectCannotIssueCodeAfterRacingBlockAndUnblock(t *testing.T) {
	app, admin, dir := setup(t)
	g := &pausedReconnectRemoval{entered: make(chan struct{}), release: make(chan struct{})}
	app.SetGateway(g)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	old := enrolledMachine(t, alice)
	if response := admin.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}}); response.Code != 404 {
		t.Fatalf("admin replaced foreign machine %d", response.Code)
	}
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetGateway(g)
	otherAdmin := *admin
	otherAdmin.handler = second.Handler()
	alice.request("GET", "/machines", nil)
	g.pause.Store(true)
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() { done <- alice.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}}) }()
	select {
	case <-g.entered:
	case <-time.After(time.Second):
		t.Fatal("replacement did not reach removal")
	}
	otherAdmin.request("GET", "/admin/users", nil)
	if w := otherAdmin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 303 {
		close(g.release)
		t.Fatal(w.Code, w.Body.String())
	}
	if w := otherAdmin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 303 {
		close(g.release)
		t.Fatal(w.Code, w.Body.String())
	}
	close(g.release)
	w := <-done
	if w.Code == 201 || strings.Contains(w.Body.String(), `"code"`) {
		t.Fatalf("pre-block replacement issued code %d %s", w.Code, w.Body.String())
	}
	if response := agentContact(t, alice, old, `{"ready":false}`); response.Code != 401 {
		t.Fatal("old credential revived")
	}
	if status := signIn(alice, "alice", password); status != 303 {
		t.Fatal(status)
	}
	alice.request("GET", "/machines", nil)
	w = alice.request("POST", "/machines/1/reconnect", url.Values{"revision": {"3"}})
	if w.Code != 201 {
		t.Fatalf("owner cannot recover invalidated intent %d %s", w.Code, w.Body.String())
	}
}

func TestReconnectDoesNotIssueCodeUntilOldGatewayStreamsAreDrained(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	credential := enrolledMachine(t, b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "start\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
	}))
	defer upstream.Close()
	proxy := agent.NewProxy("127.0.0.1")
	defer proxy.Close()
	agentServer := httptest.NewServer(proxy)
	defer agentServer.Close()
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, agentServer.Listener.Addr().String())
	})
	lifecyclePublication(t, b, "drain-reconnect", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	json.Unmarshal(agentContact(t, b, credential, `{"ready":false}`).Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	writer := &blockedHTTPWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if p := recover(); p != nil && p != http.ErrAbortHandler {
				t.Errorf("forwarding panic %v", p)
			}
		}()
		app.Handler().ServeHTTP(writer, httptest.NewRequest("GET", "https://drain-reconnect.example.test/stream", nil))
	}()
	released := false
	defer func() {
		if !released {
			close(writer.release)
		}
		<-done
	}()
	select {
	case <-writer.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("stream did not reach slow downstream")
	}
	b.request("GET", "/machines", nil)
	values := url.Values{"csrf": {b.csrf}, "revision": {"1"}}
	request := httptest.NewRequest("POST", origin+"/machines/1/reconnect", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	for _, cookie := range b.cookies {
		request.AddCookie(cookie)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	response := httptest.NewRecorder()
	b.handler.ServeHTTP(response, request.WithContext(ctx))
	if response.Code != 503 || strings.Contains(response.Body.String(), `"code"`) {
		t.Fatalf("unconfirmed gateway drain issued code %d %s", response.Code, response.Body.String())
	}
	denied := httptest.NewRecorder()
	app.Handler().ServeHTTP(denied, httptest.NewRequest("GET", "https://drain-reconnect.example.test/", nil))
	if denied.Code != 503 {
		t.Fatal("old admission reopened")
	}
	close(writer.release)
	released = true
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("old downstream did not finish")
	}
	if response := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"2"}}); response.Code != 201 {
		t.Fatalf("drained replacement retry %d %s", response.Code, response.Body.String())
	}
}

func TestReconnectDisabledAgentRecoversLostEnrollmentResponseWithoutEnabling(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	app, err := cabinet.Open(t.TempDir(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetGateway(testGateway{})
	if err := app.CreateAdministrator("owner", password); err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	endpoint, _ := url.Parse(server.URL)
	b := &browser{t: t, cookies: map[string]*http.Cookie{}, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = endpoint.Host
		r.Header.Set("Origin", server.URL)
		handler.ServeHTTP(w, r)
	})}
	b.login()
	enrolledMachine(t, b)
	b.request("GET", "/machines", nil)
	if w := b.request("POST", "/machines/1/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	response := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"2"}})
	if response.Code != 201 {
		t.Fatal(response.Code, response.Body.String())
	}
	var next struct{ Code string }
	json.Unmarshal(response.Body.Bytes(), &next)
	var drop atomic.Bool
	drop.Store(true)
	server.Config.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/agent/enroll" && drop.CompareAndSwap(true, false) {
			result := httptest.NewRecorder()
			handler.ServeHTTP(result, r)
			if result.Code != 201 {
				t.Errorf("initial disabled registration: %d %s", result.Code, result.Body.String())
			}
			http.Error(w, "lost enrollment response", 503)
			return
		}
		handler.ServeHTTP(w, r)
	})
	dir := t.TempDir()
	if _, err := agent.Enroll(context.Background(), dir, server.URL, next.Code, server.Client()); err == nil {
		t.Fatal("lost response unexpectedly succeeded")
	}
	state, err := agent.Enroll(context.Background(), dir, server.URL, next.Code, server.Client())
	if err != nil {
		t.Fatalf("disabled client trapped after consumed code: %v", err)
	}
	if state.PendingCode != "" || len(state.Control.Routes) != 0 || state.Control.MachineID != 1 {
		t.Fatalf("disabled recovered state: %+v", state.Control)
	}

	recoverWith := func(credential, publicKey string) int {
		r := httptest.NewRequest("POST", origin+"/api/agent/recover", strings.NewReader(`{"public_key":"`+publicKey+`"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+credential)
		w := httptest.NewRecorder()
		b.handler.ServeHTTP(w, r)
		return w.Code
	}
	if code := recoverWith(strings.Repeat("x", 43), state.PublicKey); code != 401 {
		t.Fatalf("wrong bearer recovered metadata %d", code)
	}
	if code := recoverWith(state.Credential, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="); code != 401 {
		t.Fatalf("wrong local public key recovered metadata %d", code)
	}
	if w := agentContact(t, b, state.Credential, `{"ready":false}`); w.Code != 401 {
		t.Fatal("metadata recovery enabled machine")
	}
}

func TestReconnectCodeCannotBeClaimedByConcurrentSecondAgent(t *testing.T) {
	app, b, dir := setup(t)
	app.SetGateway(testGateway{})
	b.login()
	enrolledMachine(t, b)
	b.request("GET", "/machines", nil)
	response := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}})
	if response.Code != 201 {
		t.Fatal(response.Code, response.Body.String())
	}
	var next struct{ Code string }
	json.Unmarshal(response.Body.Bytes(), &next)
	g := &heldEnrollmentGateway{entered: make(chan struct{}, 1), release: make(chan struct{})}
	app.SetGateway(g)
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetGateway(g)
	other := *b
	other.handler = second.Handler()
	done := make(chan *httptest.ResponseRecorder, 1)
	go func() {
		done <- reconnectEnroll(t, b, next.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("n", 43))
	}()
	select {
	case <-g.entered:
	case <-time.After(time.Second):
		t.Fatal("new enrollment did not start")
	}
	response = reconnectEnroll(t, &other, next.Code, "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("s", 43))
	if response.Code != 401 {
		close(g.release)
		t.Fatal("second agent claimed same code", response.Code)
	}
	close(g.release)
	if response := <-done; response.Code != 201 {
		t.Fatal(response.Code, response.Body.String())
	}
}

func TestReconnectMigrationKeepsPreviouslyIssuedInitialCodeUsable(t *testing.T) {
	app, b, dir := setup(t)
	app.SetGateway(testGateway{})
	b.login()
	code := createEnrollmentCode(t, b, "Older cabinet unused code")
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	// Persist a version04 fixture made before new machine creation recorded the
	// initial desired-on intent. No explicit disable was possible before enrollment.
	legacy, err := sql.Open("sqlite", filepath.Join(dir, "sreda.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	_, err = legacy.Exec(`UPDATE machines SET desired_enabled=0,access_state='Отключено' WHERE id=1`)
	legacy.Close()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetGateway(testGateway{})
	b.handler = reopened.Handler()
	credential := strings.Repeat("n", 43)
	if w := reconnectEnroll(t, b, code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", credential); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := agentContact(t, b, credential, `{"ready":false}`); w.Code != 200 {
		t.Fatalf("upgrade silently disabled never-enrolled machine %d %s", w.Code, w.Body.String())
	}
}
