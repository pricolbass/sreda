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
	"sync"
	"testing"
)

func enrolledMachine(t *testing.T, b *browser) string {
	t.Helper()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Publication machine"}})
	var code struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &code); err != nil {
		t.Fatal(err)
	}
	credential := strings.Repeat("e", 43)
	r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+code.Code+`","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","credential":"`+credential+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatalf("enroll %d %s", w.Code, w.Body.String())
	}
	return credential
}
func agentContact(t *testing.T, b *browser, credential string, body string) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest("POST", origin+"/api/agent/heartbeat", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+credential)
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	return w
}
func TestPublicationIsPendingUntilAgentAcknowledgesRouteGeneration(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	credential := enrolledMachine(t, b)
	b.request("GET", "/publications", nil)
	created := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "target": {"127.0.0.1:8080"}, "subdomain": {"photos"}})
	if created.Code != 201 {
		t.Fatalf("publication: %d %s", created.Code, created.Body.String())
	}
	var publication struct {
		ID    string `json:"id"`
		URL   string `json:"url"`
		State string `json:"state"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &publication); err != nil {
		t.Fatal(err)
	}
	if publication.URL != "https://photos.example.test" || publication.State != "Настраивается" {
		t.Fatalf("premature ready: %+v", publication)
	}
	contact := agentContact(t, b, credential, `{"ready":true,"applied_generation":0}`)
	if contact.Code != 200 {
		t.Fatalf("heartbeat %d %s", contact.Code, contact.Body.String())
	}
	var control struct {
		Generation uint64 `json:"generation"`
		Routes     []struct{ ID, Target string }
	}
	if err := json.Unmarshal(contact.Body.Bytes(), &control); err != nil {
		t.Fatal(err)
	}
	if control.Generation != 1 || len(control.Routes) != 1 || control.Routes[0].ID != publication.ID || control.Routes[0].Target != "127.0.0.1:8080" {
		t.Fatalf("wrong agent map: %s", contact.Body.String())
	}
	if w := agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	detail := b.request(http.MethodGet, "/publications/"+publication.ID, nil)
	if detail.Code != 200 || !strings.Contains(detail.Body.String(), "Настроена") {
		t.Fatalf("ack not reflected: %d %s", detail.Code, detail.Body.String())
	}
}

func TestPublishedHTTPSRequestReachesRegisteredApplicationWithoutCabinetLimits(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	credential := enrolledMachine(t, b)
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("X-Sreda-Proxy-Token") != "" || r.Header.Get("X-Sreda-Publication") != "" {
			t.Error("internal routing credential leaked")
		}
		w.Header().Set("X-App-Host", r.Host)
		w.Write([]byte(r.URL.RequestURI() + ":" + r.Header.Get("Authorization") + ":" + string(body)))
	}))
	defer upstream.Close()
	proxy := agent.NewProxy("127.0.0.1")
	defer proxy.Close()
	agentServer := httptest.NewServer(proxy)
	defer agentServer.Close()
	// Only the external WireGuard network boundary is redirected. No real WG/LXC claim.
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "10.203.0.2:9080" {
			t.Errorf("unexpected private destination %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, agentServer.Listener.Addr().String())
	})
	b.request("GET", "/publications", nil)
	created := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "target": {strings.TrimPrefix(upstream.URL, "http://")}, "subdomain": {"application"}})
	if created.Code != 201 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	response := agentContact(t, b, credential, `{"ready":true,"applied_generation":0}`)
	var control agentprotocol.Control
	if err := json.Unmarshal(response.Body.Bytes(), &control); err != nil {
		t.Fatal(err)
	}
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	if w := agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	gateway := httptest.NewTLSServer(app.Handler())
	defer gateway.Close()
	payload := strings.Repeat("z", 9000)
	request, _ := http.NewRequest("POST", gateway.URL+"/api/items?q=1", strings.NewReader(payload))
	request.Host = "application.example.test"
	request.Header.Set("Authorization", "Bearer app-user")
	request.Header.Set("X-Sreda-Proxy-Token", "forged")
	request.Header.Set("X-Sreda-Publication", "neighbor")
	result, err := gateway.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Body.Close()
	body, _ := io.ReadAll(result.Body)
	if result.StatusCode != 200 || string(body) != "/api/items?q=1:Bearer app-user:"+payload || result.Header.Get("X-App-Host") != "application.example.test" {
		t.Fatalf("public request %d %s", result.StatusCode, body)
	}
	if result.Header.Get("Content-Security-Policy") != "" || len(result.Cookies()) != 0 {
		t.Fatal("cabinet policies/cookies leaked into application")
	}
	secondApplication := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"application":"second-api"}`))
	}))
	defer secondApplication.Close()
	secondCreated := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"api"}, "target": {strings.TrimPrefix(secondApplication.URL, "http://")}})
	if secondCreated.Code != 201 {
		t.Fatalf("second app create: %d %s", secondCreated.Code, secondCreated.Body.String())
	}
	snapshot := agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	if err := json.Unmarshal(snapshot.Body.Bytes(), &control); err != nil {
		t.Fatal(err)
	}
	if control.Generation != 2 || len(control.Routes) != 2 {
		t.Fatal("second application did not reuse machine map")
	}
	if err := proxy.ApplyControl(control); err != nil {
		t.Fatal(err)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":2}`)
	apiRequest, _ := http.NewRequest("GET", gateway.URL+"/v1/items", nil)
	apiRequest.Host = "api.example.test"
	apiResponse, err := gateway.Client().Do(apiRequest)
	if err != nil {
		t.Fatal(err)
	}
	apiBody, _ := io.ReadAll(apiResponse.Body)
	apiResponse.Body.Close()
	if apiResponse.StatusCode != 200 || string(apiBody) != `{"application":"second-api"}` {
		t.Fatalf("second API request %d %s", apiResponse.StatusCode, apiBody)
	}
	t.Run("CaddyWildcardHTTPS", func(t *testing.T) {
		client, address := caddyClient(t, app.Handler())
		req, _ := http.NewRequest("POST", address+"/through-caddy", strings.NewReader("caddy-body"))
		req.Header.Set("Authorization", "Bearer caddy-user")
		response, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode != 200 || string(body) != "/through-caddy:Bearer caddy-user:caddy-body" {
			t.Fatalf("Caddy data path: %d %s", response.StatusCode, body)
		}
	})

}

func TestAgentRejectsNewMapWithoutBreakingExistingPublication(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	credential := enrolledMachine(t, b)
	b.request("GET", "/publications", nil)
	create := func(label, target string) PublicationResult {
		w := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "target": {target}, "subdomain": {label}})
		if w.Code != 201 && w.Code != 200 {
			t.Fatalf("create %d %s", w.Code, w.Body.String())
		}
		var result PublicationResult
		json.Unmarshal(w.Body.Bytes(), &result)
		return result
	}
	first := create("good", "127.0.0.1:8080")
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	bad := create("unassigned", "192.0.2.33:8080")
	if w := agentContact(t, b, credential, `{"ready":true,"applied_generation":1,"failed_generation":2,"apply_error":"Адрес не принадлежит машине"}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w := b.request("GET", "/publications/"+first.ID, nil); !strings.Contains(w.Body.String(), "Настроена") {
		t.Fatalf("existing route damaged: %s", w.Body.String())
	}
	if w := b.request("GET", "/publications/"+bad.ID, nil); !strings.Contains(w.Body.String(), "Ошибка") || !strings.Contains(w.Body.String(), "Адрес не принадлежит машине") {
		t.Fatalf("failed route claims success: %s", w.Body.String())
	}
	duplicate := create("unassigned", "192.0.2.33:8080")
	if duplicate.ID != bad.ID {
		t.Fatal("retry created duplicate publication")
	}
	b.request("GET", "/publications", nil)
	if w := b.request("POST", "/publications/"+bad.ID+"/retry", nil); w.Code != 303 {
		t.Fatal(w.Code)
	}
	w := agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	var control agentprotocol.Control
	json.Unmarshal(w.Body.Bytes(), &control)
	if control.Generation != 3 || len(control.Routes) != 2 {
		t.Fatalf("retry map: %s", w.Body.String())
	}
}

type PublicationResult struct {
	ID string `json:"id"`
}

func TestPublicationNameCollisionAndInvalidTargetsDoNotCreateAnotherRoute(t *testing.T) {
	app, b, dir := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	enrolledMachine(t, b)
	b.request("GET", "/publications", nil)
	for _, input := range []url.Values{
		{"machine_id": {"1"}, "subdomain": {"sreda"}, "target": {"127.0.0.1:8080"}},
		{"machine_id": {"1"}, "subdomain": {"UpperCase"}, "target": {"127.0.0.1:8080"}},
		{"machine_id": {"1"}, "subdomain": {"app"}, "target": {"neighbor.example.test:8080"}},
		{"machine_id": {"1"}, "subdomain": {"app"}, "target": {"10.203.0.3:8080"}},
		{"machine_id": {"1"}, "subdomain": {"app"}, "target": {"127.0.0.1:0"}},
	} {
		if w := b.request("POST", "/publications", input); w.Code != 400 {
			t.Fatalf("invalid input accepted: %d %s", w.Code, w.Body.String())
		}
	}
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	clients := []*browser{visitor(t, b), visitor(t, b)}
	clients[1].handler = second.Handler()
	for _, client := range clients {
		client.csrf = b.csrf
		for name, cookie := range b.cookies {
			client.cookies[name] = cookie
		}
	}
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for i, client := range clients {
		wg.Add(1)
		go func(i int, client *browser) {
			defer wg.Done()
			codes <- client.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"contested"}, "target": {[]string{"127.0.0.1:8080", "127.0.0.1:9090"}[i]}}).Code
		}(i, client)
	}
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[201] != 1 || counts[409] != 1 {
		t.Fatalf("name collision: %+v", counts)
	}
}
func TestPublicationOwnershipCoversMachineAndPublicationIdentifiers(t *testing.T) {
	app, admin, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	admin.login()
	person := func(login string) *browser {
		link := invitation(t, admin, "24h")
		p := visitor(t, admin)
		if status := accept(t, p, link, login); status != 303 {
			t.Fatal(status)
		}
		p.request("GET", "/login", nil)
		if w := p.request("POST", "/login", url.Values{"login": {login}, "password": {password}}); w.Code != 303 {
			t.Fatal(w.Code)
		}
		return p
	}
	alice, bob := person("alice"), person("bob")
	enrolledMachine(t, alice)
	alice.request("GET", "/publications", nil)
	created := alice.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"aliceapp"}, "target": {"127.0.0.1:8080"}})
	if created.Code != 201 {
		t.Fatal(created.Code)
	}
	var p PublicationResult
	json.Unmarshal(created.Body.Bytes(), &p)
	bob.request("GET", "/publications", nil)
	if w := bob.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"stolen"}, "target": {"127.0.0.1:8080"}}); w.Code != 404 {
		t.Fatalf("foreign machine publish: %d", w.Code)
	}
	if w := bob.request("GET", "/publications/"+p.ID, nil); w.Code != 404 {
		t.Fatalf("foreign publication read: %d", w.Code)
	}
	if w := bob.request("POST", "/publications/"+p.ID+"/retry", nil); w.Code != 404 {
		t.Fatalf("foreign publication mutation: %d", w.Code)
	}
	if w := bob.request("GET", "/publications", nil); strings.Contains(w.Body.String(), "aliceapp") {
		t.Fatal("foreign publication leaked in list")
	}
	if w := admin.request("GET", "/publications", nil); !strings.Contains(w.Body.String(), "aliceapp") || !strings.Contains(w.Body.String(), "alice") {
		t.Fatal("admin cannot inspect publication owner")
	}
}
