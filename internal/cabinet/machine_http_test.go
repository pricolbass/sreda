package cabinet_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
	"strings"
	"sync"
	"testing"
)

type testGateway struct{}

func (testGateway) Details() tunnel.Details {
	return tunnel.Details{GatewayPublicKey: "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: "gateway.example.test:51820", GatewayAddress: "10.203.0.1/32"}
}
func (testGateway) ApplyPeer(context.Context, tunnel.Peer) error  { return nil }
func (testGateway) RemovePeer(context.Context, tunnel.Peer) error { return nil }

func TestMachineEnrollmentIsSingleUseAndControlCredentialIsPrivate(t *testing.T) {
	app, b, dir := setup(t)
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetGateway(testGateway{})
	app.SetGateway(testGateway{}) // external adapter fixture: this is not a WireGuard acceptance test.
	b.login()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Debian web"}})
	if created.Code != 201 {
		t.Fatalf("create: %d %s", created.Code, created.Body.String())
	}
	var invitation struct {
		Code string `json:"code"`
		ID   int64  `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &invitation); err != nil || invitation.Code == "" {
		t.Fatalf("code not returned: %v %s", err, created.Body.String())
	}
	payload := `{"code":"` + invitation.Code + `","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","credential":"` + strings.Repeat("c", 43) + `"}`
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for i := range 2 {
		handler := []http.Handler{b.handler, second.Handler()}[i]
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)
			codes <- w.Code
		}()
	}
	wg.Wait()
	close(codes)
	successes := 0
	for code := range codes {
		if code == 201 {
			successes++
		} else if code != 401 {
			t.Fatalf("enroll status: %d", code)
		}
	}
	if successes != 1 {
		t.Fatalf("single-use success count %d", successes)
	}
	r := httptest.NewRequest("POST", origin+"/api/agent/heartbeat", strings.NewReader(`{"ready":true}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("c", 43))
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("heartbeat: %d %s", w.Code, w.Body.String())
	}
	listing := b.request("GET", "/machines", nil)
	if listing.Code != 200 || !strings.Contains(listing.Body.String(), "На связи") || strings.Contains(listing.Body.String(), invitation.Code) || strings.Contains(listing.Body.String(), strings.Repeat("c", 43)) {
		t.Fatalf("machine view leaked secret or missing state: %d %s", listing.Code, listing.Body.String())
	}
	_ = http.MethodGet
}

func TestNetworkFailurePreservesCodeAndDoesNotClaimContact(t *testing.T) {
	app, b, _ := setup(t)
	b.login()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Waiting for network"}})
	var enrollment struct {
		Code string `json:"code"`
	}
	json.Unmarshal(created.Body.Bytes(), &enrollment)
	enroll := func() *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+enrollment.Code+`","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","credential":"`+strings.Repeat("d", 43)+`"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		b.handler.ServeHTTP(w, r)
		return w
	}
	if w := enroll(); w.Code != 503 {
		t.Fatalf("unconfigured network accepted enrollment: %d", w.Code)
	}
	app.SetGateway(testGateway{})
	if w := enroll(); w.Code != 201 {
		t.Fatalf("code lost after network failure: %d %s", w.Code, w.Body.String())
	}
	listing := b.request("GET", "/machines", nil)
	if strings.Contains(listing.Body.String(), "На связи") || !strings.Contains(listing.Body.String(), "Ещё не было") {
		t.Fatalf("enrollment claimed contact: %s", listing.Body.String())
	}
}

func TestMachineOwnershipIncludesDirectIdentifierAccess(t *testing.T) {
	_, admin, _ := setup(t)
	admin.login()
	newUser := func(login string) *browser {
		link := invitation(t, admin, "24h")
		person := visitor(t, admin)
		if code := accept(t, person, link, login); code != 303 {
			t.Fatal(code)
		}
		person.request("GET", "/login", nil)
		if w := person.request("POST", "/login", url.Values{"login": {login}, "password": {password}}); w.Code != 303 {
			t.Fatal(w.Code)
		}
		return person
	}
	alice := newUser("alice")
	bob := newUser("bob")
	alice.request("GET", "/machines", nil)
	if w := alice.request("POST", "/machines", url.Values{"name": {"Alice private machine"}}); w.Code != 201 {
		t.Fatalf("create: %d", w.Code)
	}
	if w := bob.request("GET", "/machines", nil); strings.Contains(w.Body.String(), "Alice private machine") {
		t.Fatal("foreign machine visible in list")
	}
	if w := bob.request("GET", "/machines/1", nil); w.Code != 404 {
		t.Fatalf("foreign ID accessible: %d", w.Code)
	}
	if w := alice.request("GET", "/machines/1", nil); w.Code != 200 {
		t.Fatalf("owner ID inaccessible: %d", w.Code)
	}
	if w := admin.request("GET", "/machines", nil); !strings.Contains(w.Body.String(), "Alice private machine") || !strings.Contains(w.Body.String(), "alice") {
		t.Fatal("administrator cannot inspect owner")
	}
	if w := visitor(t, admin).request("GET", "/machines/1", nil); w.Code != 303 {
		t.Fatalf("anonymous ID accessible: %d", w.Code)
	}
}

func TestExistingMachineKeyCannotBeReassignedByAnotherEnrollment(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	b.login()
	create := func(name string) string {
		b.request("GET", "/machines", nil)
		response := b.request("POST", "/machines", url.Values{"name": {name}})
		if response.Code != 201 {
			t.Fatalf("create: %d", response.Code)
		}
		var result struct {
			Code string `json:"code"`
		}
		if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result.Code
	}
	enroll := func(code, key, credential string) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]string{"code": code, "public_key": key, "credential": credential})
		request := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(string(body)))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		b.handler.ServeHTTP(response, request)
		return response
	}
	key := "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	if response := enroll(create("First machine"), key, strings.Repeat("a", 43)); response.Code != 201 {
		t.Fatalf("first: %d", response.Code)
	}
	second := create("Second machine")
	if response := enroll(second, key, strings.Repeat("b", 43)); response.Code != 400 {
		t.Fatalf("reused key: %d %s", response.Code, response.Body.String())
	}
	if response := enroll(second, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("b", 43)); response.Code != 201 {
		t.Fatalf("fresh key lost code: %d %s", response.Code, response.Body.String())
	}
}
