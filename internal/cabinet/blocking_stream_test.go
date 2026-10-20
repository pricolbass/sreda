package cabinet_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"sreda/internal/tunnel"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestBlockClosesManualHTTPAndAgentWebSocketAndPreservesOtherOwner(t *testing.T) {
	app, admin, _ := setup(t)
	app.SetGateway(&observingGateway{latest: time.Now()})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	bob := createOrdinary(t, admin, "bob")
	signIn(bob, "bob", password)
	httpStopped := make(chan struct{})
	wsStopped := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/stream":
			w.Header().Set("Content-Type", "text/event-stream")
			io.WriteString(w, "start\n")
			w.(http.Flusher).Flush()
			<-r.Context().Done()
			close(httpStopped)
		case "/socket":
			conn, buffer, err := w.(http.Hijacker).Hijack()
			if err != nil {
				return
			}
			defer conn.Close()
			defer close(wsStopped)
			buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
			buffer.Write([]byte{0x81, 2, 'o', 'k'})
			buffer.Flush()
			conn.Read(make([]byte, 1))
		default:
			io.WriteString(w, "healthy")
		}
	}))
	defer upstream.Close()
	proxy := agent.NewProxy("127.0.0.1")
	defer proxy.Close()
	agentServer := httptest.NewServer(proxy)
	defer agentServer.Close()
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		target := upstream.Listener.Addr().String()
		if strings.HasPrefix(address, "10.203.0.3:") {
			target = agentServer.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	})
	create := func(b *browser, mode, key, credential string) int64 {
		b.request("GET", "/machines", nil)
		w := b.request("POST", "/machines", url.Values{"name": {mode}, "mode": {mode}})
		var e struct {
			ID   int64
			Code string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		if w := enrollmentRequest(b.handler, context.Background(), e.Code, key, credential); w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
		return e.ID
	}
	publish := func(b *browser, id int64, label, target string) {
		b.request("GET", "/publications", nil)
		if w := b.request("POST", "/publications", url.Values{"machine_id": {strconv.FormatInt(id, 10)}, "subdomain": {label}, "target": {target}}); w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	manualID := create(alice, "manual", "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("m", 43))
	publish(alice, manualID, "manual-stream", "10.203.0.2:8080")
	credential := strings.Repeat("a", 43)
	agentID := create(alice, "agent", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", credential)
	publish(alice, agentID, "agent-socket", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	json.Unmarshal(agentContact(t, alice, credential, `{"ready":true}`).Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, alice, credential, `{"ready":true,"applied_generation":1}`)
	bobID := create(bob, "manual", "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("b", 43))
	publish(bob, bobID, "bob-health", "10.203.0.4:8080")
	gateway := httptest.NewTLSServer(app.Handler())
	defer gateway.Close()
	client := gateway.Client()
	client.Timeout = 5 * time.Second
	req, _ := http.NewRequest("GET", gateway.URL+"/stream", nil)
	req.Host = "manual-stream.example.test"
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	start := make([]byte, 6)
	if _, err := io.ReadFull(response.Body, start); err != nil {
		t.Fatal(err)
	}
	config := client.Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", gateway.Listener.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: agent-socket.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	reader := bufio.NewReader(conn)
	ws, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil || ws.StatusCode != 101 {
		t.Fatalf("upgrade %v %v", ws, err)
	}
	frame := make([]byte, 4)
	if _, err := io.ReadFull(reader, frame); err != nil {
		t.Fatal(err)
	}
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	for _, stopped := range []chan struct{}{httpStopped, wsStopped} {
		select {
		case <-stopped:
		case <-time.After(2 * time.Second):
			t.Fatal("established connection survived block")
		}
	}
	if _, err := io.ReadAll(response.Body); err == nil {
		t.Fatal("HTTP stream was not forcibly closed")
	}
	conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := reader.ReadByte(); err == nil {
		t.Fatal("websocket remained open")
	}
	for host, want := range map[string]int{"manual-stream.example.test": 404, "agent-socket.example.test": 404, "bob-health.example.test": 200} {
		req, _ := http.NewRequest("GET", gateway.URL+"/health", nil)
		req.Host = host
		r, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		if r.StatusCode != want {
			t.Fatalf("%s: %d %s", host, r.StatusCode, body)
		}
	}
}

func TestBlockUnconfirmedRouteStillRemovesPeerAndCanRetry(t *testing.T) {
	app, admin, _ := setup(t)
	gatewayAdapter := &interruptedEnrollmentGateway{peers: map[int64]tunnel.Peer{}}
	app.SetGateway(gatewayAdapter)
	app.ConfigurePublicationZone("example.test")
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	credential := enrolledMachine(t, alice)
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
	p := lifecyclePublication(t, alice, "blocked-writer", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	json.Unmarshal(agentContact(t, alice, credential, `{"ready":true}`).Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, alice, credential, `{"ready":true,"applied_generation":1}`)
	writer := &blockedHTTPWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer func() {
			if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
				t.Errorf("forwarding panic: %v", recovered)
			}
		}()
		app.Handler().ServeHTTP(writer, httptest.NewRequest("GET", "https://blocked-writer.example.test/stream", nil))
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
		t.Fatal("stream did not reach downstream")
	}
	admin.request("GET", "/admin/users", nil)
	values := url.Values{"revision": {"1"}, "csrf": {admin.csrf}}
	request := httptest.NewRequest("POST", origin+"/admin/users/2/block", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	for _, cookie := range admin.cookies {
		request.AddCookie(cookie)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	response := httptest.NewRecorder()
	admin.handler.ServeHTTP(response, request.WithContext(ctx))
	if response.Code != 503 {
		t.Fatalf("unconfirmed route %d %s", response.Code, response.Body.String())
	}
	if len(gatewayAdapter.peers) != 0 || gatewayAdapter.removeCount[1] == 0 {
		t.Fatal("route timeout prevented peer removal")
	}
	if gatewayAdapter.cleanupCanceled {
		t.Fatal("peer cleanup inherited canceled request")
	}
	if w := admin.request("GET", "/admin/users", nil); strings.Contains(w.Body.String(), "<p>Доступ закрыт</p>") {
		t.Fatal("unconfirmed route reported closed")
	}
	close(writer.release)
	released = true
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("downstream did not finish")
	}
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatalf("closure retry %d %s", w.Code, w.Body.String())
	}
	if got := publicationDetail(t, admin, p.ID); got.State != "Отключена" {
		t.Fatal(got.State)
	}
}
