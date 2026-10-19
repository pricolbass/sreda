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
	"regexp"
	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
	"strconv"
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

func TestManualHTTPSDeliveryAndExplicitReenableReuseSameConnection(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(&observingGateway{latest: time.Now().Add(-130 * time.Second)})
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
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Sreda-Proxy-Token") != "" || r.Header.Get("X-Sreda-Publication") != "" {
			t.Error("manual app received internal route credential")
		}
		w.Write([]byte("app reached " + r.URL.RequestURI()))
	}))
	defer upstream.Close()
	app.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != "10.203.0.2:8080" {
			t.Errorf("wrong manual destination %s", address)
		}
		return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
	})
	var first struct {
		ID       string `json:"id"`
		Revision int64  `json:"revision"`
	}
	for _, label := range []string{"manual-one", "manual-two"} {
		b.request("GET", "/publications", nil)
		created = b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {label}, "target": {"10.203.0.2:8080"}})
		if created.Code != 201 {
			t.Fatalf("create %d %s", created.Code, created.Body.String())
		}
		if label == "manual-one" {
			json.Unmarshal(created.Body.Bytes(), &first)
		}
	}
	gateway := httptest.NewTLSServer(app.Handler())
	defer gateway.Close()
	get := func(label string) int {
		request, _ := http.NewRequest("GET", gateway.URL+"/probe?x=1", nil)
		request.Host = label + ".example.test"
		request.Header.Set("X-Sreda-Proxy-Token", "forged")
		response, err := gateway.Client().Do(request)
		if err != nil {
			t.Fatal(err)
		}
		defer response.Body.Close()
		body, _ := io.ReadAll(response.Body)
		if response.StatusCode == 200 && string(body) != "app reached /probe?x=1" {
			t.Fatalf("unexpected app response %s", body)
		}
		return response.StatusCode
	}
	if code := get("manual-one"); code != 200 {
		t.Fatalf("manual handshake130s considered unavailable: %d", code)
	}
	if changed := b.request("POST", "/publications/"+first.ID+"/disable", url.Values{"revision": {strconv.FormatInt(first.Revision, 10)}}); changed.Code != 303 {
		t.Fatalf("disable %d %s", changed.Code, changed.Body.String())
	}
	if code := get("manual-one"); code != 503 {
		t.Fatalf("disabled manual publication: %d", code)
	}
	if code := get("manual-two"); code != 200 {
		t.Fatalf("unrelated manual publication: %d", code)
	}
	details := b.request("GET", "/publications/"+first.ID, nil)
	json.Unmarshal(details.Body.Bytes(), &first)
	if changed := b.request("POST", "/publications/"+first.ID+"/enable", url.Values{"revision": {strconv.FormatInt(first.Revision, 10)}}); changed.Code != 303 {
		t.Fatalf("enable %d %s", changed.Code, changed.Body.String())
	}
	if code := get("manual-one"); code != 200 {
		t.Fatalf("manual enable incorrectly waits for agent ack: %d", code)
	}
}

func TestManualBrowserPageUsesUniqueNonceAndLocalKeyFallback(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	b.login()
	b.request("GET", "/machines", nil)
	values := url.Values{"name": {"Manual browser"}, "mode": {"manual"}, "csrf": {b.csrf}}
	r := httptest.NewRequest("POST", origin+"/machines", strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", origin)
	r.Header.Set("Accept", "text/html")
	for _, cookie := range b.cookies {
		r.AddCookie(cookie)
	}
	page := httptest.NewRecorder()
	b.handler.ServeHTTP(page, r)
	if page.Code != 201 {
		t.Fatalf("browser page %d %s", page.Code, page.Body.String())
	}
	match := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(page.Header().Get("Content-Security-Policy"))
	if len(match) != 2 || !strings.Contains(page.Body.String(), `<script nonce="`+match[1]+`">`) || !strings.Contains(page.Body.String(), "X25519") || !strings.Contains(page.Body.String(), "wg pubkey") {
		t.Fatal("browser generation or strict nonce/fallback missing")
	}
	normal := b.request("GET", "/machines", nil)
	if strings.Contains(normal.Header().Get("Content-Security-Policy"), "script-src") {
		t.Fatal("manual script policy leaked to normal cabinet")
	}
	code := regexp.MustCompile(`data-code="([^"]+)"`).FindStringSubmatch(page.Body.String())
	if len(code) != 2 {
		t.Fatal("manual page has no one-time enrollment")
	}
	completed := b.request("POST", "/machines/1/wireguard", url.Values{"code": {code[1]}, "public_key": {"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}})
	if completed.Code != 201 {
		t.Fatalf("public-key fallback %d %s", completed.Code, completed.Body.String())
	}
	template := b.request("GET", "/machines/1/wireguard/template", nil)
	if template.Code != 200 || !strings.Contains(template.Body.String(), "PRIVATE_KEY_FROM_LOCAL_FILE") || !strings.Contains(template.Body.String(), "Address = 10.203.0.2/32") || strings.Contains(template.Body.String(), "proxy_token") {
		t.Fatalf("fallback template %d %s", template.Code, template.Body.String())
	}
}

type manualRetryGateway struct {
	testGateway
	unavailable bool
}

func (g *manualRetryGateway) ApplyPeer(context.Context, tunnel.Peer) error {
	if g.unavailable {
		return errors.New("apply timeout")
	}
	return nil
}
func (g *manualRetryGateway) RemovePeer(context.Context, tunnel.Peer) error {
	if g.unavailable {
		return errors.New("revocation unavailable")
	}
	return nil
}

func TestManualPublicKeyFallbackCanRetryDurablePendingEnrollment(t *testing.T) {
	app, b, _ := setup(t)
	gateway := &manualRetryGateway{unavailable: true}
	app.SetGateway(gateway)
	b.login()
	b.request("GET", "/machines", nil)
	created := b.request("POST", "/machines", url.Values{"name": {"Manual retry"}, "mode": {"manual"}})
	var pending struct {
		Code string `json:"code"`
	}
	json.Unmarshal(created.Body.Bytes(), &pending)
	values := url.Values{"code": {pending.Code}, "public_key": {"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}}
	first := b.request("POST", "/machines/1/wireguard", values)
	if first.Code != 503 {
		t.Fatalf("failed network %d %s", first.Code, first.Body.String())
	}
	gateway.unavailable = false
	retry := b.request("POST", "/machines/1/wireguard", values)
	if retry.Code != 201 {
		t.Fatalf("same public-key fallback cannot recover: %d %s", retry.Code, retry.Body.String())
	}
}
