package cabinet_test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestPublicationDeletionWaitsForRemovedRouteAcknowledgmentBeforeReleasingName(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	credential := enrolledMachine(t, b)
	p := lifecyclePublication(t, b, "reusable", "127.0.0.1:8080")
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	path := "/publications/" + p.ID + "/delete"
	if w := b.request("POST", path, url.Values{"revision": {"1"}}); w.Code != 400 {
		t.Fatalf("missing name loss confirmation: %d %s", w.Code, w.Body.String())
	}
	if w := b.request("POST", path, url.Values{"revision": {"1"}, "confirm_name": {"reusable"}}); w.Code != 202 {
		t.Fatalf("delete pending: %d %s", w.Code, w.Body.String())
	}
	if got := publicationDetail(t, b, p.ID); got.State != "Удаляется" {
		t.Fatalf("delete missing: %+v", got)
	}
	if w := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"reusable"}, "target": {"127.0.0.1:9090"}}); w.Code != 409 {
		t.Fatalf("name released before agent removal: %d", w.Code)
	}
	response := agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	var control agentprotocol.Control
	if err := json.Unmarshal(response.Body.Bytes(), &control); err != nil {
		t.Fatal(err)
	}
	if control.Generation != 2 || len(control.Routes) != 0 {
		t.Fatalf("deleted route still registered: %s", response.Body.String())
	}
	if w := b.request("POST", "/publications/"+p.ID+"/enable", url.Values{"revision": {"1"}}); w.Code != 409 {
		t.Fatalf("stale enable restored deleted route: %d", w.Code)
	}
	if w := agentContact(t, b, credential, `{"ready":true,"applied_generation":2}`); w.Code != 200 {
		t.Fatalf("removal ack: %d %s", w.Code, w.Body.String())
	}
	if w := b.request("GET", "/publications/"+p.ID, nil); w.Code != 404 {
		t.Fatalf("deleted publication visible: %d", w.Code)
	}
	replacement := lifecyclePublication(t, b, "reusable", "127.0.0.1:9090")
	if replacement.ID == p.ID {
		t.Fatal("publication ID reused")
	}
	if w := b.request("POST", path, url.Values{"revision": {"1"}, "confirm_name": {"reusable"}}); w.Code != 200 {
		t.Fatalf("repeat deletion: %d %s", w.Code, w.Body.String())
	}
	if w := b.request("GET", "/publications/"+replacement.ID, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "9090") {
		t.Fatal("old deletion affected new owner of name")
	}
}

func TestMachineDeletionListsDisabledPublicationAndRevokesAgentBeforeRemoval(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	credential := enrolledMachine(t, b)
	p := lifecyclePublication(t, b, "blocking", "127.0.0.1:8080")
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	if w := b.request("POST", "/publications/"+p.ID+"/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := b.request("POST", "/machines/1/delete", nil); w.Code != 409 || !strings.Contains(w.Body.String(), "blocking") {
		t.Fatalf("disabled publication not listed as blocker: %d %s", w.Code, w.Body.String())
	}
	if w := b.request("POST", "/publications/"+p.ID+"/delete", url.Values{"revision": {"2"}, "confirm_name": {"blocking"}}); w.Code != 202 {
		t.Fatalf("publication deletion: %d %s", w.Code, w.Body.String())
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":3}`)
	if w := b.request("POST", "/machines/1/delete", nil); w.Code != 200 {
		t.Fatalf("machine removal: %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, b, credential, `{"ready":true,"applied_generation":3}`); w.Code != 401 {
		t.Fatalf("deleted machine credential usable: %d", w.Code)
	}
	if w := b.request("GET", "/machines/1", nil); w.Code != 404 {
		t.Fatalf("deleted machine remains: %d", w.Code)
	}
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"new machine"}})
	if created.Code != 201 || !strings.Contains(created.Body.String(), `"id":2`) {
		t.Fatalf("machine ID reused: %d %s", created.Code, created.Body.String())
	}
}

type removalGateway struct {
	testGateway
	fail atomic.Bool
}

func (g *removalGateway) RemovePeer(context.Context, tunnel.Peer) error {
	if g.fail.Load() {
		return errors.New("fixture: removal not confirmed")
	}
	return nil
}
func TestMachineDeletionKeepsReservationAndRevokesCredentialsOnKernelFailure(t *testing.T) {
	app, b, _ := setup(t)
	gateway := &removalGateway{}
	gateway.fail.Store(true)
	app.SetGateway(gateway)
	b.login()
	credential := enrolledMachine(t, b)
	if w := b.request("POST", "/machines/1/delete", nil); w.Code != 503 {
		t.Fatalf("failed kernel cleanup claimed removal: %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, b, credential, `{"ready":true}`); w.Code != 401 {
		t.Fatalf("credential survived delete intent: %d", w.Code)
	}
	page := b.request("GET", "/machines", nil)
	if !strings.Contains(page.Body.String(), "Удаляется") || !strings.Contains(page.Body.String(), "не подтверждён") {
		t.Fatalf("pending removal invisible: %s", page.Body.String())
	}
	if w := b.request("GET", "/machines/1", nil); w.Code != 200 {
		t.Fatal("machine reservation lost before cleanup")
	}
	gateway.fail.Store(false)
	if w := b.request("POST", "/machines/1/delete", nil); w.Code != 200 {
		t.Fatalf("cleanup retry: %d %s", w.Code, w.Body.String())
	}
	if w := b.request("POST", "/machines/1/delete", nil); w.Code != 200 {
		t.Fatalf("idempotent machine deletion: %d", w.Code)
	}
}

func TestPublicationDeletionTimeoutReservesNameUntilBothAgentAndGatewayAreClosed(t *testing.T) {
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
	p := lifecyclePublication(t, b, "slow-delete", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	json.Unmarshal(agentContact(t, b, credential, `{"ready":true,"applied_generation":0}`).Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	writer := &blockedHTTPWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer func() { recover(); close(done) }()
		app.Handler().ServeHTTP(writer, httptest.NewRequest("GET", "https://slow-delete.example.test/stream", nil))
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
		t.Fatal("stream did not block")
	}
	values := url.Values{"csrf": {b.csrf}, "revision": {"1"}, "confirm_name": {"slow-delete"}}
	request := httptest.NewRequest("POST", origin+"/publications/"+p.ID+"/delete", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	for _, cookie := range b.cookies {
		request.AddCookie(cookie)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	response := httptest.NewRecorder()
	b.handler.ServeHTTP(response, request.WithContext(ctx))
	if response.Code != 503 {
		t.Fatalf("blocked closure claimed deletion: %d %s", response.Code, response.Body.String())
	}
	snapshot := agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	json.Unmarshal(snapshot.Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":2}`)
	if w := b.request("GET", "/publications/"+p.ID, nil); w.Code != 200 {
		t.Fatal("agent ACK released name before gateway drain")
	}
	if w := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"slow-delete"}, "target": {"127.0.0.1:9090"}}); w.Code != 409 {
		t.Fatal("name freed after timeout")
	}
	close(writer.release)
	released = true
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("blocked response did not finish")
	}
	if w := b.request("POST", "/publications/"+p.ID+"/delete", url.Values{"revision": {"1"}, "confirm_name": {"slow-delete"}}); w.Code != 200 {
		t.Fatalf("drained retry: %d %s", w.Code, w.Body.String())
	}
}

func TestConcurrentPublicationCreationAndMachineDeletionCannotBothCommit(t *testing.T) {
	app, b, dir := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	enrolledMachine(t, b)
	b.request("GET", "/publications", nil)
	other, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetGateway(testGateway{})
	deleteBrowser := visitor(t, b)
	deleteBrowser.handler = other.Handler()
	deleteBrowser.csrf = b.csrf
	for name, cookie := range b.cookies {
		deleteBrowser.cookies[name] = cookie
	}
	start := make(chan struct{})
	created := make(chan int, 1)
	deleted := make(chan int, 1)
	go func() {
		<-start
		created <- b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"concurrent"}, "target": {"127.0.0.1:8080"}}).Code
	}()
	go func() { <-start; deleted <- deleteBrowser.request("POST", "/machines/1/delete", nil).Code }()
	close(start)
	creation, deletion := <-created, <-deleted
	if creation == 201 {
		if deletion != 409 {
			t.Fatalf("creation+deletion both committed: %d %d", creation, deletion)
		}
	} else if deletion == 200 {
		if creation != 404 && creation != 409 {
			t.Fatalf("creation after deletion: %d", creation)
		}
	} else {
		t.Fatalf("unexpected concurrent outcome: %d %d", creation, deletion)
	}
}

type heldEnrollmentGateway struct {
	testGateway
	entered chan struct{}
	release chan struct{}
}

func (g *heldEnrollmentGateway) ApplyPeer(ctx context.Context, _ tunnel.Peer) error {
	select {
	case g.entered <- struct{}{}:
	default:
	}
	select {
	case <-g.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func TestDeletionWaitsForConcurrentEnrollmentCleanupBeforeFreeingMachine(t *testing.T) {
	app, b, dir := setup(t)
	gateway := &heldEnrollmentGateway{entered: make(chan struct{}, 1), release: make(chan struct{})}
	app.SetGateway(gateway)
	b.login()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"inflight"}})
	var invite struct {
		Code string `json:"code"`
	}
	json.Unmarshal(created.Body.Bytes(), &invite)
	body := `{"code":"` + invite.Code + `","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","credential":"` + strings.Repeat("x", 43) + `"}`
	enrollmentDone := make(chan int, 1)
	go func() {
		r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		b.handler.ServeHTTP(w, r)
		enrollmentDone <- w.Code
	}()
	select {
	case <-gateway.entered:
	case <-time.After(2 * time.Second):
		t.Fatal("enrollment did not reach gateway")
	}
	other, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	other.SetGateway(gateway)
	deleter := visitor(t, b)
	deleter.handler = other.Handler()
	deleter.csrf = b.csrf
	for name, cookie := range b.cookies {
		deleter.cookies[name] = cookie
	}
	w := deleter.request("POST", "/machines/1/delete", nil)
	if w.Code != 202 {
		close(gateway.release)
		<-enrollmentDone
		t.Fatalf("live enrollment not awaited: %d %s", w.Code, w.Body.String())
	}
	close(gateway.release)
	if status := <-enrollmentDone; status != 503 {
		t.Fatalf("stale enrollment promoted after deletion intent: %d", status)
	}
	if w := deleter.request("POST", "/machines/1/delete", nil); w.Code != 200 {
		t.Fatalf("enrollment cleanup did not unblock deletion: %d %s", w.Code, w.Body.String())
	}
}
