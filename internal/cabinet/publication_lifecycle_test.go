package cabinet_test

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http/httptest"
	"net/url"
	"sreda/internal/cabinet"
	"sreda/internal/publication"
	"testing"
)

func lifecyclePublication(t *testing.T, b *browser, label, target string) publication.Publication {
	t.Helper()
	b.request("GET", "/publications", nil)
	response := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {label}, "target": {target}})
	if response.Code != 201 {
		t.Fatalf("create: %d %s", response.Code, response.Body.String())
	}
	var result publication.Publication
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func publicationDetail(t *testing.T, b *browser, id string) publication.Publication {
	t.Helper()
	response := b.request("GET", "/publications/"+id, nil)
	if response.Code != 200 {
		t.Fatalf("detail: %d", response.Code)
	}
	var result publication.Publication
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func TestDisablePreservesPublicationAndStaleEnableCannotReopenIt(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	credential := enrolledMachine(t, b)
	p := lifecyclePublication(t, b, "kept", "127.0.0.1:8080")
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	if response := b.request("POST", "/publications/"+p.ID+"/disable", url.Values{"revision": {"1"}}); response.Code != 303 {
		t.Fatalf("disable: %d %s", response.Code, response.Body.String())
	}
	disabled := publicationDetail(t, b, p.ID)
	if disabled.State != "Отключена" || disabled.URL != p.URL || disabled.Target != p.Target || disabled.Revision != 2 {
		t.Fatalf("lost disabled publication: %+v", disabled)
	}
	if response := b.request("POST", "/publications/"+p.ID+"/enable", url.Values{"revision": {"1"}}); response.Code != 409 {
		t.Fatalf("stale enable: %d", response.Code)
	}
	if response := b.request("POST", "/publications/"+p.ID+"/disable", url.Values{"revision": {"1"}}); response.Code != 303 {
		t.Fatalf("repeat disable: %d", response.Code)
	}
	if response := b.request("POST", "/publications/"+p.ID+"/enable", url.Values{"revision": {"2"}}); response.Code != 303 {
		t.Fatalf("enable: %d %s", response.Code, response.Body.String())
	}
	if got := publicationDetail(t, b, p.ID); got.State != "Настраивается" || got.Revision != 3 {
		t.Fatalf("enable did not await new map: %+v", got)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	if got := publicationDetail(t, b, p.ID); got.State != "Настраивается" {
		t.Fatalf("old acknowledgment reopened publication: %+v", got)
	}
	agentContact(t, b, credential, `{"ready":true,"applied_generation":3}`)
	if got := publicationDetail(t, b, p.ID); got.State != "Настроена" || got.URL != p.URL {
		t.Fatalf("new acknowledgment: %+v", got)
	}
}

func TestDisabledPublicationSurvivesRestartAndOldAgentAcknowledgment(t *testing.T) {
	app, b, dir := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	credential := enrolledMachine(t, b)
	p := lifecyclePublication(t, b, "persisted", "127.0.0.1:8080")
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	if response := b.request("POST", "/publications/"+p.ID+"/disable", url.Values{"revision": {"1"}}); response.Code != 303 {
		t.Fatal(response.Code)
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	restarted.SetGateway(testGateway{})
	b.handler = restarted.Handler()
	if result := agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`); result.Code != 200 {
		t.Fatal(result.Code)
	}
	if got := publicationDetail(t, b, p.ID); got.State != "Отключена" || got.URL != p.URL || got.Revision != 2 {
		t.Fatalf("restart reopened publication: %+v", got)
	}
	response := httptest.NewRecorder()
	b.handler.ServeHTTP(response, httptest.NewRequest("GET", "https://persisted.example.test/", nil))
	if response.Code != 503 {
		t.Fatalf("restart admitted old route: %d", response.Code)
	}
}

func TestUnavailableAgentDoesNotPreventGatewayDisable(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	app.SetPublicationDialer(func(context.Context, string, string) (net.Conn, error) { return nil, errors.New("agent unavailable") })
	b.login()
	credential := enrolledMachine(t, b)
	p := lifecyclePublication(t, b, "unavailable", "127.0.0.1:8080")
	agentContact(t, b, credential, `{"ready":true,"applied_generation":1}`)
	response := httptest.NewRecorder()
	b.handler.ServeHTTP(response, httptest.NewRequest("GET", "https://unavailable.example.test/", nil))
	if response.Code != 503 {
		t.Fatalf("unavailable agent: %d", response.Code)
	}
	if response := b.request("POST", "/publications/"+p.ID+"/disable", url.Values{"revision": {"1"}}); response.Code != 303 {
		t.Fatalf("agent was required to disable: %d %s", response.Code, response.Body.String())
	}
	if got := publicationDetail(t, b, p.ID); got.State != "Отключена" {
		t.Fatalf("gateway closure not confirmed: %+v", got)
	}
}
