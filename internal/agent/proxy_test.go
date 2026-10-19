package agent_test

import (
	"net/http"
	"net/http/httptest"
	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"strings"
	"testing"
)

func TestProxyUsesRegisteredLoopbackTargetAndRejectsStaleControl(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Sreda-Proxy-Token") != "" {
			t.Error("gateway credential leaked upstream")
		}
		w.Write([]byte(r.URL.RequestURI() + ":" + r.Header.Get("Authorization")))
	}))
	defer upstream.Close()
	proxy := agent.NewProxy("10.203.0.1")
	control := agentprotocol.Control{ProxyToken: strings.Repeat("p", 43), Generation: 1, Routes: []agentprotocol.Route{{ID: "app1", Target: strings.TrimPrefix(upstream.URL, "http://"), Enabled: true}}}
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	request := func(id string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", "http://app.example.test/path?q=1", nil)
		r.RemoteAddr = "10.203.0.1:45678"
		r.Header.Set("X-Sreda-Proxy-Token", control.ProxyToken)
		r.Header.Set("X-Sreda-Publication", id)
		r.Header.Set("Authorization", "Bearer app-user")
		w := httptest.NewRecorder()
		proxy.ServeHTTP(w, r)
		return w
	}
	if w := request("app1"); w.Code != 200 || w.Body.String() != "/path?q=1:Bearer app-user" {
		t.Fatalf("proxy: %d %s", w.Code, w.Body.String())
	}
	if w := request("127.0.0.1:22"); w.Code != 404 {
		t.Fatalf("caller selected target: %d", w.Code)
	}
	control.Generation = 2
	control.Routes = nil
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	if w := request("app1"); w.Code != 404 {
		t.Fatalf("disabled route remains reachable: %d", w.Code)
	}
	control.Generation = 1
	control.Routes = []agentprotocol.Route{{ID: "app1", Target: strings.TrimPrefix(upstream.URL, "http://"), Enabled: true}}
	if err := proxy.ApplyControl(control); err == nil {
		t.Fatal("stale routes accepted")
	}
	control.Generation = 3
	control.Routes[0].Target = "10.203.0.2:8080"
	if err := proxy.ApplyControl(control); err == nil {
		t.Fatal("neighbor tunnel target accepted")
	}
}

func TestSuspendedProxyResumesSameGenerationWithoutAcceptingOlderControl(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.Write([]byte("resumed")) }))
	defer upstream.Close()
	proxy := agent.NewProxy("10.203.0.1")
	control := agentprotocol.Control{ProxyToken: strings.Repeat("p", 43), Generation: 5, Routes: []agentprotocol.Route{{ID: "app1", Target: strings.TrimPrefix(upstream.URL, "http://"), Enabled: true}}}
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	proxy.Close()
	stale := control
	stale.Generation = 4
	if err := proxy.ApplyControl(stale); err == nil {
		t.Fatal("suspension discarded the monotonic version guard")
	}
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "http://app.example.test/", nil)
	r.RemoteAddr = "10.203.0.1:4000"
	r.Header.Set("X-Sreda-Proxy-Token", control.ProxyToken)
	r.Header.Set("X-Sreda-Publication", "app1")
	w := httptest.NewRecorder()
	proxy.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != "resumed" {
		t.Fatalf("same snapshot did not resume route: %d %s", w.Code, w.Body.String())
	}
}
