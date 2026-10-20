package cabinet_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestSetupPromptUsesCurrentAgentPublicationAndExcludesConnectionCredentials(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	b.login()
	credential := enrolledMachine(t, b)
	created := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {"notes"}, "target": {"127.0.0.1:8080"}})
	if created.Code != 201 {
		t.Fatal(created.Code)
	}
	var p struct {
		ID string `json:"id"`
	}
	json.Unmarshal(created.Body.Bytes(), &p)
	prompt := b.request("GET", "/publications/"+p.ID+"/setup-prompt", nil)
	if prompt.Code != 200 {
		t.Fatalf("prompt %d %s", prompt.Code, prompt.Body.String())
	}
	for _, value := range []string{"https://notes.example.test", "127.0.0.1:8080", "10.203.0.2/32", "X-Forwarded-Proto", "Скопировать промпт для настройки"} {
		if !strings.Contains(prompt.Body.String(), value) {
			t.Fatalf("missing context %q", value)
		}
	}
	connection, err := app.MachineConnection(context.Background(), 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{credential, connection.ProxyToken, password} {
		if strings.Contains(prompt.Body.String(), secret) {
			t.Fatal("prompt contains connection/account credential")
		}
	}
	if anon := visitor(t, b).request("GET", "/publications/"+p.ID+"/setup-prompt", nil); anon.Code != 303 {
		t.Fatalf("anonymous prompt %d", anon.Code)
	}
}

func TestSetupPromptManualParametersAndSelectionStayWithResourceOwner(t *testing.T) {
	app, admin, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	admin.login()
	person := visitor(t, admin)
	if code := accept(t, person, invitation(t, admin, "24h"), "alice"); code != 303 {
		t.Fatal(code)
	}
	person.request("GET", "/login", nil)
	if w := person.request("POST", "/login", url.Values{"login": {"alice"}, "password": {password}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	person.request("GET", "/machines", nil)
	created := person.request("POST", "/machines", url.Values{"name": {"Manual app"}, "mode": {"manual"}})
	var pending struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &pending); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+pending.Code+`","public_key":"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=","credential":"`+strings.Repeat("m", 43)+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	person.handler.ServeHTTP(w, r)
	if w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	person.request("GET", "/publications", nil)
	for _, selection := range []struct{ name, target string }{{"one", "10.203.0.2:8080"}, {"two", "10.203.0.2:9090"}} {
		response := person.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {selection.name}, "target": {selection.target}})
		if response.Code != 201 {
			t.Fatal(response.Code, response.Body.String())
		}
		var p struct {
			ID string `json:"id"`
		}
		json.Unmarshal(response.Body.Bytes(), &p)
		path := "/publications/" + p.ID + "/setup-prompt"
		prompt := person.request("GET", path, nil)
		for _, expected := range []string{"ручной WireGuard", "самостоятельно", selection.target, "https://" + selection.name + ".example.test"} {
			if !strings.Contains(prompt.Body.String(), expected) {
				t.Fatalf("missing %q", expected)
			}
		}
		for _, secret := range []string{pending.Code, strings.Repeat("m", 43), password} {
			if strings.Contains(prompt.Body.String(), secret) {
				t.Fatal("secret in manual prompt")
			}
		}
		if foreign := admin.request("GET", path, nil); foreign.Code != 404 {
			t.Fatalf("admin can obtain another owner's setup context: %d", foreign.Code)
		}
	}
	if foreign := admin.request("GET", "/machines/1/setup-prompt", nil); foreign.Code != 404 {
		t.Fatal(foreign.Code)
	}
	machine := person.request("GET", "/machines/1/setup-prompt", nil)
	if machine.Code != 200 || !strings.Contains(machine.Body.String(), "Публикация ещё не выбрана") || strings.Contains(machine.Body.String(), "https://two.example.test") {
		t.Fatal("machine prompt accidentally selected publication")
	}
}
