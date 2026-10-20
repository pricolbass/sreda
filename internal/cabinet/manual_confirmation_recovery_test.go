package cabinet_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sreda/internal/cabinet"
	"strings"
	"testing"
	"time"
)

func TestManualReconnectRecoversPublicationConfirmationAfterCommittedEnrollment(t *testing.T) {
	for _, enrollment := range []string{"browser", "api"} {
		t.Run(enrollment, func(t *testing.T) {
			app, b, dir := setup(t)
			app.SetGateway(testGateway{})
			if err := app.ConfigurePublicationZone("example.test"); err != nil {
				t.Fatal(err)
			}
			b.login()
			b.request("GET", "/machines", nil)
			created := b.request("POST", "/machines", url.Values{"name": {"Manual"}, "mode": {"manual"}})
			var code struct{ Code string }
			if err := json.Unmarshal(created.Body.Bytes(), &code); err != nil {
				t.Fatal(err)
			}
			if w := reconnectEnroll(t, b, code.Code, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("m", 43)); w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			createPublication := func(name string) string {
				t.Helper()
				b.request("GET", "/publications", nil)
				w := b.request("POST", "/publications", url.Values{"machine_id": {"1"}, "subdomain": {name}, "target": {"10.203.0.2:8080"}})
				if w.Code != 201 {
					t.Fatal(w.Code, w.Body.String())
				}
				var p struct{ ID string }
				if err := json.Unmarshal(w.Body.Bytes(), &p); err != nil {
					t.Fatal(err)
				}
				return p.ID
			}
			live, off := createPublication("recover-manual"), createPublication("remain-off")
			if w := b.request("POST", "/publications/"+off+"/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
				t.Fatal(w.Code, w.Body.String())
			}
			b.request("GET", "/machines", nil)
			w := b.request("POST", "/machines/1/reconnect", url.Values{"revision": {"1"}})
			if w.Code != 201 {
				t.Fatal(w.Code, w.Body.String())
			}
			if err := json.Unmarshal(w.Body.Bytes(), &code); err != nil {
				t.Fatal(err)
			}
			// A real SQLite failure exposes the crash window after the machine
			// commits its replacement peer and consumes the code, before publication confirmation.
			db, err := sql.Open("sqlite", filepath.Join(dir, "sreda.sqlite3"))
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			if _, err := db.Exec(`CREATE TRIGGER fail_manual_confirmation BEFORE UPDATE OF state ON publications WHEN NEW.state='Настроена' BEGIN SELECT RAISE(ABORT,'confirmation interrupted'); END`); err != nil {
				t.Fatal(err)
			}
			if enrollment == "browser" {
				w = b.request("POST", "/machines/1/wireguard", url.Values{"code": {code.Code}, "public_key": {"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}})
			} else {
				w = reconnectEnroll(t, b, code.Code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("n", 43))
			}
			if w.Code < 500 {
				t.Fatalf("SQLite confirmation failure not observed: %d %s", w.Code, w.Body.String())
			}
			if current := publicationDetail(t, b, live); current.State != "Настраивается" {
				t.Fatalf("crash window not retained: %+v", current)
			}
			if _, err := db.Exec(`DROP TRIGGER fail_manual_confirmation`); err != nil {
				t.Fatal(err)
			}
			if err := app.Close(); err != nil {
				t.Fatal(err)
			}
			reopened, err := cabinet.Open(dir, "")
			if err != nil {
				t.Fatal(err)
			}
			defer reopened.Close()
			reopened.SetGateway(&observingGateway{latest: time.Now()})
			b.handler = reopened.Handler()
			if w := reconnectEnroll(t, b, code.Code, "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("x", 43)); w.Code != 401 {
				t.Fatalf("committed code remained usable: %d", w.Code)
			}
			for i := 0; i < 2; i++ {
				if err := reopened.ReconcileMachinePeers(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if current := publicationDetail(t, b, live); current.State != "Настроена" || !current.DesiredEnabled {
				t.Fatalf("manual confirmation was not recovered: %+v", current)
			}
			if current := publicationDetail(t, b, off); current.State != "Отключена" || current.DesiredEnabled {
				t.Fatalf("recovery reopened disabled publication: %+v", current)
			}
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "restored manual application") }))
			defer upstream.Close()
			reopened.SetPublicationDialer(func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
			})
			served := httptest.NewRecorder()
			reopened.Handler().ServeHTTP(served, httptest.NewRequest("GET", "https://recover-manual.example.test/", nil))
			if served.Code != 200 || served.Body.String() != "restored manual application" {
				t.Fatalf("restored address unavailable: %d %s", served.Code, served.Body.String())
			}
		})
	}
}
