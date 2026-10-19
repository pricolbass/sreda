package cabinet_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
	"strings"
	"testing"
	"time"
)

func TestManualEnrollmentCannotReturnAgentSecretsOrClaimHeartbeatContact(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	b.login()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Manual Debian"}, "mode": {"manual"}})
	if created.Code != 201 {
		t.Fatalf("create %d %s", created.Code, created.Body.String())
	}
	var pending struct {
		Code string `json:"code"`
		ID   int64  `json:"id"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	credential := strings.Repeat("m", 43)
	request := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+pending.Code+`","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","credential":"`+credential+`"}`))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	b.handler.ServeHTTP(response, request)
	if response.Code != 201 {
		t.Fatalf("enroll %d %s", response.Code, response.Body.String())
	}
	var result map[string]any
	json.Unmarshal(response.Body.Bytes(), &result)
	if _, ok := result["proxy_token"]; ok {
		t.Fatal("manual connection received agent proxy token")
	}
	heartbeat := agentContact(t, b, credential, `{"ready":true}`)
	if heartbeat.Code != 401 {
		t.Fatalf("manual heartbeat accepted: %d", heartbeat.Code)
	}
	page := b.request("GET", "/machines", nil)
	if strings.Contains(page.Body.String(), "На связи") {
		t.Fatal("manual enrollment fabricated contact")
	}
}

func TestManualParametersReferToSameMachineWithoutCredentials(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	b.login()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Manual Debian"}, "mode": {"manual"}})
	var pending struct {
		Code string `json:"code"`
	}
	json.Unmarshal(created.Body.Bytes(), &pending)
	key := "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+pending.Code+`","public_key":"`+key+`","credential":"`+strings.Repeat("m", 43)+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	params := b.request("GET", "/machines/1/wireguard", nil)
	if params.Code != 200 {
		t.Fatalf("parameters %d %s", params.Code, params.Body.String())
	}
	var dto struct {
		ID        int64  `json:"machine_id"`
		PublicKey string `json:"public_key"`
		Address   string `json:"address"`
	}
	if err := json.Unmarshal(params.Body.Bytes(), &dto); err != nil {
		t.Fatal(err)
	}
	if dto.ID != 1 || dto.Address != "10.203.0.2/32" || dto.PublicKey != key {
		t.Fatalf("wrong connection: %s", params.Body.String())
	}
	if strings.Contains(params.Body.String(), "proxy_token") || strings.Contains(params.Body.String(), "credential") || strings.Contains(params.Body.String(), "private_key") || strings.Contains(params.Body.String(), pending.Code) {
		t.Fatal("secret in public parameters")
	}
	if anon := visitor(t, b).request("GET", "/machines/1/wireguard", nil); anon.Code != 303 {
		t.Fatalf("anonymous parameters %d", anon.Code)
	}
}

func TestManualPublicationRequiresItsOwnTunnelAddress(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Manual Debian"}, "mode": {"manual"}})
	var pending struct {
		Code string `json:"code"`
	}
	json.Unmarshal(created.Body.Bytes(), &pending)
	r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+pending.Code+`","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","credential":"`+strings.Repeat("m", 43)+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	for _, target := range []string{"127.0.0.1:8080", "10.203.0.3:8080", "192.168.1.10:8080"} {
		b.request("GET", "/publications", nil)
		response := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"manual"}, "target": {target}})
		if response.Code != 400 {
			t.Fatalf("foreign target %s accepted: %d %s", target, response.Code, response.Body.String())
		}
	}
	response := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"manual"}, "target": {"10.203.0.2:8080"}})
	if response.Code != 201 || !strings.Contains(response.Body.String(), "Настроена") {
		t.Fatalf("manual route not applied without agent: %d %s", response.Code, response.Body.String())
	}
}

type observingGateway struct {
	testGateway
	latest time.Time
	fail   bool
}

func (g *observingGateway) LatestHandshake(context.Context, tunnel.Peer) (time.Time, error) {
	if g.fail {
		return time.Time{}, errors.New("observer unavailable")
	}
	return g.latest, nil
}

func TestManualContactUsesHandshakeAndDoesNotTrustPersistedTimestampAfterObservationFailure(t *testing.T) {
	app, b, dir := setup(t)
	app.SetGateway(&observingGateway{latest: time.Now()})
	b.login()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Manual Debian"}, "mode": {"manual"}})
	var pending struct {
		Code string `json:"code"`
	}
	json.Unmarshal(created.Body.Bytes(), &pending)
	r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+pending.Code+`","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","credential":"`+strings.Repeat("m", 43)+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Code)
	}
	page := b.request("GET", "/machines", nil)
	if !strings.Contains(page.Body.String(), "На связи") {
		t.Fatalf("handshake not reflected: %s", page.Body.String())
	}
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetGateway(&observingGateway{fail: true})
	b.handler = second.Handler()
	page = b.request("GET", "/machines", nil)
	if strings.Contains(page.Body.String(), "На связи") || !strings.Contains(page.Body.String(), "Нет связи") {
		t.Fatalf("stale contact trusted after failed observation: %s", page.Body.String())
	}
}
