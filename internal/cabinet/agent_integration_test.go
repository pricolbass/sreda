package cabinet_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"sreda/internal/agent"
	"sreda/internal/cabinet"
	"strings"
	"testing"
)

func TestAgentEnrollmentPersistsPrivateCredentialsAcrossRestart(t *testing.T) {
	server := httptest.NewTLSServer(nil)
	defer server.Close()
	app, err := cabinet.Open(t.TempDir(), server.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	app.SetGateway(testGateway{})
	if err = app.CreateAdministrator("owner", password); err != nil {
		t.Fatal(err)
	}
	handler := app.Handler()
	server.Config.Handler = handler
	endpoint, _ := url.Parse(server.URL)
	b := &browser{t: t, cookies: map[string]*http.Cookie{}, handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Host = endpoint.Host
		r.Header.Set("Origin", server.URL)
		handler.ServeHTTP(w, r)
	})}
	b.login()
	b.request("GET", "/machines", nil)
	response := b.request("POST", "/machines", url.Values{"name": {"Agent integration"}})
	var enrollment struct {
		Code string `json:"code"`
	}
	if err = json.Unmarshal(response.Body.Bytes(), &enrollment); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	state, err := agent.Enroll(context.Background(), dir, server.URL, enrollment.Code, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	if state.Control.MachineID != 1 || state.Control.Address != "10.203.0.2/32" || state.PendingCode != "" {
		t.Fatalf("wrong machine connected: %+v", state.Control)
	}
	restarted, err := agent.LoadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if restarted.PrivateKey != state.PrivateKey || restarted.Credential != state.Credential {
		t.Fatal("credentials did not survive restart")
	}
	info, err := os.Stat(dir + "/state.json")
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0600 {
		t.Fatal("agent credentials file is readable by others")
	}
	if _, err = agent.Enroll(context.Background(), t.TempDir(), server.URL, enrollment.Code, server.Client()); err == nil {
		t.Fatal("same code enrolled a second agent")
	}
	page := b.request("GET", "/machines", nil).Body.String()
	for _, secret := range []string{state.PrivateKey, state.Credential, state.Control.ProxyToken, enrollment.Code} {
		if strings.Contains(page, secret) {
			t.Fatal("machine listing leaked secret")
		}
	}
}
