package cabinet_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sreda/internal/tunnel"
	"strings"
	"sync"
	"testing"
)

type testGateway struct{}

func (testGateway) Details() tunnel.Details {
	return tunnel.Details{GatewayPublicKey: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", Endpoint: "gateway.example.test:51820", GatewayAddress: "10.203.0.1/32"}
}
func (testGateway) ApplyPeer(context.Context, tunnel.Peer) error  { return nil }
func (testGateway) RemovePeer(context.Context, tunnel.Peer) error { return nil }

func TestMachineEnrollmentIsSingleUseAndControlCredentialIsPrivate(t *testing.T) {
	app, b, _ := setup(t)
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
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(payload))
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			b.handler.ServeHTTP(w, r)
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
