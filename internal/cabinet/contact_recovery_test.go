package cabinet_test

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"sreda/internal/cabinet"
	"strings"
	"testing"
	"time"
)

func TestBothConnectionModesResumeSamePublicationAfterContactReturnsAndKeepDisabledClosed(t *testing.T) {
	app, b, dir := setup(t)
	app.Close()
	now := time.Now().UTC().Truncate(time.Second)
	app, err := cabinet.OpenWithOptions(dir, "", cabinet.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	b.handler = app.Handler()
	gateway := &observingGateway{latest: now}
	app.SetGateway(gateway)
	app.ConfigurePublicationZone("example.test")
	b.login()
	credential := enrolledMachine(t, b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "same application") }))
	defer upstream.Close()
	proxy := agent.NewProxy("127.0.0.1")
	defer proxy.Close()
	agentServer := httptest.NewServer(proxy)
	defer agentServer.Close()
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		target := upstream.Listener.Addr().String()
		if strings.HasSuffix(address, ":9080") {
			target = agentServer.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, target)
	})
	p := lifecyclePublication(t, b, "contact-agent", strings.TrimPrefix(upstream.URL, "http://"))
	disabled := lifecyclePublication(t, b, "contact-disabled", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	json.Unmarshal(agentContact(t, b, credential, `{"ready":true}`).Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":2}`)
	if w := b.request("POST", "/publications/"+disabled.ID+"/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Manual"}, "mode": {"manual"}})
	var pending struct{ Code string }
	json.Unmarshal(created.Body.Bytes(), &pending)
	if w := enrollmentRequest(b.handler, context.Background(), pending.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("m", 43)); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	b.request("GET", "/publications", nil)
	manual := b.request("POST", "/publications", url.Values{"machine_id": {"2"}, "subdomain": {"contact-manual"}, "target": {"10.203.0.3:8080"}})
	if manual.Code != 201 {
		t.Fatal(manual.Code, manual.Body.String())
	}
	request := func(label string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		app.Handler().ServeHTTP(w, httptest.NewRequest("GET", "https://"+label+".example.test/", nil))
		return w
	}
	for _, label := range []string{"contact-agent", "contact-manual"} {
		if w := request(label); w.Code != 200 || w.Body.String() != "same application" {
			t.Fatalf("initial %s: %d %s", label, w.Code, w.Body.String())
		}
	}
	now = now.Add(181 * time.Second)
	for _, label := range []string{"contact-agent", "contact-manual"} {
		if w := request(label); w.Code != 503 || !strings.Contains(w.Body.String(), "Сервис временно недоступен") {
			t.Fatalf("lost contact %s: %d %s", label, w.Code, w.Body.String())
		}
	}
	if page := b.request("GET", "/machines", nil); strings.Contains(page.Body.String(), "На связи") || !strings.Contains(page.Body.String(), "Нет связи") || strings.Contains(page.Body.String(), "Ещё не было") {
		t.Fatal("contact history lost or online fabricated")
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":2}`)
	now = now.Add(31 * time.Second)
	gateway.latest = now
	for _, label := range []string{"contact-agent", "contact-manual"} {
		if w := request(label); w.Code != 200 || w.Body.String() != "same application" {
			t.Fatalf("contact return %s: %d %s", label, w.Code, w.Body.String())
		}
	}
	if w := request("contact-disabled"); w.Code != 503 {
		t.Fatal("contact return reopened disabled publication")
	}
	if got := publicationDetail(t, b, p.ID); got.URL != p.URL || !got.DesiredEnabled {
		t.Fatalf("publication recreated: %+v", got)
	}
}

func TestCaddyProcessRestartKeepsConfiguredAndDisabledPublicationIntent(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	credential := enrolledMachine(t, b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "same process behind restarted TLS") }))
	defer upstream.Close()
	proxy := agent.NewProxy("127.0.0.1")
	defer proxy.Close()
	agentServer := httptest.NewServer(proxy)
	defer agentServer.Close()
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, agentServer.Listener.Addr().String())
	})
	p := lifecyclePublication(t, b, "application", strings.TrimPrefix(upstream.URL, "http://"))
	off := lifecyclePublication(t, b, "application-off", strings.TrimPrefix(upstream.URL, "http://"))
	var control agentprotocol.Control
	json.Unmarshal(agentContact(t, b, credential, `{"ready":true}`).Body.Bytes(), &control)
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":2}`)
	if w := b.request("POST", "/publications/"+off.ID+"/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	client, address, restart := caddyClientWithRestart(t, app.Handler())
	check := func() {
		response, err := client.Get(address)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(response.Body)
		response.Body.Close()
		if response.StatusCode != 200 || string(body) != "same process behind restarted TLS" {
			t.Fatalf("HTTPS after restore: %d %s", response.StatusCode, body)
		}
		response, err = client.Get(strings.Replace(address, "application.", "application-off.", 1))
		if err != nil {
			t.Fatal(err)
		}
		response.Body.Close()
		if response.StatusCode != 503 {
			t.Fatal("Caddy restart reopened disabled publication")
		}
	}
	check()
	restart()
	check()
	if got := publicationDetail(t, b, p.ID); got.URL != p.URL || got.ID != p.ID {
		t.Fatal("Caddy restart recreated publication")
	}
}
