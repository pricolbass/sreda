package cabinet_test

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDisableClosesActiveHTTPStreamAndLeavesOtherPublicationAndAppRunning(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	credential := enrolledMachine(t, b)
	stopped := make(chan struct{}, 1)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/stream" {
			_, _ = io.WriteString(w, "healthy")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "start\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		stopped <- struct{}{}
	}))
	defer upstream.Close()
	proxy := agent.NewProxy("127.0.0.1")
	defer proxy.Close()
	agentServer := httptest.NewServer(proxy)
	defer agentServer.Close()
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, agentServer.Listener.Addr().String())
	})
	first := lifecyclePublication(t, b, "streaming", strings.TrimPrefix(upstream.URL, "http://"))
	second := lifecyclePublication(t, b, "unaffected", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	if err := json.Unmarshal(agentContact(t, b, credential, `{"ready":true,"applied_generation":0}`).Body.Bytes(), &control); err != nil {
		t.Fatal(err)
	}
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":2}`)
	gateway := httptest.NewTLSServer(app.Handler())
	defer gateway.Close()
	client := gateway.Client()
	client.Timeout = 5 * time.Second
	request, _ := http.NewRequest("GET", gateway.URL+"/stream", nil)
	request.Host = "streaming.example.test"
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	firstBytes := make([]byte, 6)
	if _, err = io.ReadFull(response.Body, firstBytes); err != nil || string(firstBytes) != "start\n" {
		t.Fatalf("stream did not start: %q %v", firstBytes, err)
	}
	if w := b.request("POST", "/publications/"+first.ID+"/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatalf("disable stream: %d %s", w.Code, w.Body.String())
	}
	select {
	case <-stopped:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream stream stayed open")
	}
	if _, err = io.ReadAll(response.Body); err == nil {
		t.Fatal("active stream ended without forced closure")
	}
	if got := publicationDetail(t, b, first.ID); got.State != "Отключена" {
		t.Fatalf("not disabled: %+v", got)
	}
	for _, host := range []string{"unaffected.example.test", "streaming.example.test"} {
		request, _ := http.NewRequest("GET", gateway.URL+"/health", nil)
		request.Host = host
		result, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(result.Body)
		result.Body.Close()
		if host == "unaffected.example.test" && (result.StatusCode != 200 || string(body) != "healthy") {
			t.Fatalf("other publication damaged: %d %s", result.StatusCode, body)
		}
		if host == "streaming.example.test" && result.StatusCode != 503 {
			t.Fatalf("disabled address reopened: %d", result.StatusCode)
		}
	}
	result, err := http.Get(upstream.URL + "/health")
	if err != nil {
		t.Fatal(err)
	}
	result.Body.Close()
	if result.StatusCode != 200 {
		t.Fatal("application stopped")
	}
	if got := publicationDetail(t, b, second.ID); got.State != "Настроена" {
		t.Fatal("other publication state changed")
	}
}

func TestDisableClosesEstablishedWebSocket(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	credential := enrolledMachine(t, b)
	stopped := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		defer conn.Close()
		defer close(stopped)
		_, _ = buffer.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n")
		_, _ = buffer.Write([]byte{0x81, 2, 'o', 'k'})
		_ = buffer.Flush()
		one := make([]byte, 1)
		_, _ = conn.Read(one)
	}))
	defer upstream.Close()
	proxy := agent.NewProxy("127.0.0.1")
	defer proxy.Close()
	agentServer := httptest.NewServer(proxy)
	defer agentServer.Close()
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, agentServer.Listener.Addr().String())
	})
	p := lifecyclePublication(t, b, "socket", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	_ = json.Unmarshal(agentContact(t, b, credential, `{"ready":true,"applied_generation":0}`).Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	gateway := httptest.NewTLSServer(app.Handler())
	defer gateway.Close()
	config := gateway.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 3 * time.Second}, "tcp", gateway.Listener.Addr().String(), config)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	_, err = io.WriteString(conn, "GET /socket HTTP/1.1\r\nHost: socket.example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n")
	if err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	response, err := http.ReadResponse(reader, &http.Request{Method: "GET"})
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != 101 {
		t.Fatalf("upgrade: %d", response.StatusCode)
	}
	frame := make([]byte, 4)
	if _, err = io.ReadFull(reader, frame); err != nil || string(frame[2:]) != "ok" {
		t.Fatalf("websocket frame %v %v", frame, err)
	}
	if result := b.request("POST", "/publications/"+p.ID+"/disable", url.Values{"revision": {"1"}}); result.Code != 303 {
		t.Fatalf("disable websocket: %d %s", result.Code, result.Body.String())
	}
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err = reader.ReadByte(); err == nil {
		t.Fatal("websocket stayed readable after disable")
	}
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("upstream websocket stayed connected")
	}
}

// A downstream socket that cannot accept bytes or honor deadlines models an
// unconfirmed close at the HTTP system seam; application collaborators are real.
type blockedHTTPWriter struct {
	header           http.Header
	entered, release chan struct{}
	once             sync.Once
}

func (w *blockedHTTPWriter) Header() http.Header { return w.header }
func (w *blockedHTTPWriter) WriteHeader(int)     {}
func (w *blockedHTTPWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.entered) })
	<-w.release
	return 0, io.ErrClosedPipe
}
func (w *blockedHTTPWriter) Flush() {}
func (w *blockedHTTPWriter) SetWriteDeadline(time.Time) error {
	return errors.New("downstream cannot confirm deadline")
}

func TestUnconfirmedStreamClosureRemainsErrorAndCanBeRetried(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	credential := enrolledMachine(t, b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			_, _ = io.WriteString(w, "healthy")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "start\n")
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
	p := lifecyclePublication(t, b, "hanging", strings.TrimPrefix(upstream.URL, "http://"))
	lifecyclePublication(t, b, "still-open", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	_ = json.Unmarshal(agentContact(t, b, credential, `{"ready":true,"applied_generation":0}`).Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":2}`)
	writer := &blockedHTTPWriter{header: make(http.Header), entered: make(chan struct{}), release: make(chan struct{})}
	done := make(chan struct{})
	go func() {
		defer func() {
			if recovered := recover(); recovered != nil && recovered != http.ErrAbortHandler {
				t.Errorf("forwarding panic: %v", recovered)
			}
			close(done)
		}()
		app.Handler().ServeHTTP(writer, httptest.NewRequest("GET", "https://hanging.example.test/stream", nil))
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
		t.Fatal("downstream did not block")
	}
	values := url.Values{"revision": {"1"}, "csrf": {b.csrf}}
	request := httptest.NewRequest("POST", origin+"/publications/"+p.ID+"/disable", strings.NewReader(values.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	for _, cookie := range b.cookies {
		request.AddCookie(cookie)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 400*time.Millisecond)
	defer cancel()
	response := httptest.NewRecorder()
	disableDone := make(chan struct{})
	go func() { b.handler.ServeHTTP(response, request.WithContext(ctx)); close(disableDone) }()
	defer func() { <-disableDone }()
	until := time.Now().Add(200 * time.Millisecond)
	for publicationDetail(t, b, p.ID).State != "Отключается" {
		if time.Now().After(until) {
			t.Fatal("disable did not persist intent")
		}
		time.Sleep(time.Millisecond)
	}
	otherDone := make(chan int, 1)
	go func() {
		other := httptest.NewRecorder()
		b.handler.ServeHTTP(other, httptest.NewRequest("GET", "https://still-open.example.test/health", nil))
		otherDone <- other.Code
	}()
	select {
	case status := <-otherDone:
		if status != 200 {
			t.Fatalf("unrelated publication: %d", status)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("one slow publication blocked unrelated access")
	}
	<-disableDone
	if response.Code != 503 {
		t.Fatalf("unconfirmed close: %d %s", response.Code, response.Body.String())
	}
	if got := publicationDetail(t, b, p.ID); got.State != "Ошибка" || got.Error == "" {
		t.Fatalf("unconfirmed closure claimed success: %+v", got)
	}
	denied := httptest.NewRecorder()
	b.handler.ServeHTTP(denied, httptest.NewRequest("GET", "https://hanging.example.test/", nil))
	if denied.Code != 503 {
		t.Fatalf("pending closure admitted traffic: %d", denied.Code)
	}
	close(writer.release)
	released = true
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("downstream did not release")
	}
	if response := b.request("POST", "/publications/"+p.ID+"/disable", url.Values{"revision": {"1"}}); response.Code != 303 {
		t.Fatalf("cleanup retry: %d %s", response.Code, response.Body.String())
	}
	if got := publicationDetail(t, b, p.ID); got.State != "Отключена" || got.URL != p.URL {
		t.Fatalf("cleanup did not finish safely: %+v", got)
	}
}
