package cabinet_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sreda/internal/cabinet"
	"strings"
	"testing"
)

func TestPublicationsUseConfiguredHTTPSPort(t *testing.T) {
	for _, port := range []string{":8443", ":443"} {
		t.Run(port, func(t *testing.T) {
			base := origin + port
			app, err := cabinet.Open(t.TempDir(), base)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { app.Close() })
			if err = app.CreateAdministrator("owner", password); err != nil {
				t.Fatal(err)
			}
			if err = app.ConfigurePublicationZone("example.test"); err != nil {
				t.Fatal(err)
			}
			app.SetGateway(testGateway{})
			b := &browser{t: t, handler: app.Handler(), cookies: map[string]*http.Cookie{}, origin: base}
			b.login()
			code := createEnrollmentCode(t, b, "Local HTTPS machine")
			input, _ := json.Marshal(map[string]string{"code": code, "public_key": "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "credential": strings.Repeat("e", 43)})
			r := httptest.NewRequest("POST", base+"/api/agent/enroll", strings.NewReader(string(input))).WithContext(context.Background())
			r.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			b.handler.ServeHTTP(w, r)
			if w.Code != 201 {
				t.Fatalf("enroll: %d %s", w.Code, w.Body.String())
			}
			b.request("GET", "/publications", nil)
			created := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "target": {"127.0.0.1:8080"}, "subdomain": {"local-app"}})
			var p struct {
				URL string `json:"url"`
			}
			if created.Code != 201 || json.Unmarshal(created.Body.Bytes(), &p) != nil {
				t.Fatalf("create: %d %s", created.Code, created.Body.String())
			}
			want := "https://local-app.example.test"
			if port == ":8443" {
				want += port
			}
			if p.URL != want {
				t.Fatalf("publication URL: got %q want %q", p.URL, want)
			}
			for _, address := range []string{want, "https://local-app.example.test" + port} {
				request := httptest.NewRequest("GET", address, nil)
				response := httptest.NewRecorder()
				b.handler.ServeHTTP(response, request)
				if response.Code != http.StatusServiceUnavailable || !strings.Contains(response.Body.String(), "Сервис временно недоступен") {
					t.Fatalf("publication address %s: %d %s", address, response.Code, response.Body.String())
				}
			}
			wrong := httptest.NewRecorder()
			b.handler.ServeHTTP(wrong, httptest.NewRequest("GET", "https://local-app.example.test:9443", nil))
			if wrong.Code != http.StatusBadRequest {
				t.Fatalf("unexpected port accepted: %d", wrong.Code)
			}
		})
	}
}
