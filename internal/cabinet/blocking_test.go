package cabinet_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"net/url"
	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
	"strings"
	"testing"
)

func TestBlockRevokesSessionsAndUnblockRequiresNewLogin(t *testing.T) {
	_, admin, _ := setup(t)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("initial login")
	}
	if w := admin.request("GET", "/admin/users", nil); w.Code != 200 {
		t.Fatalf("users: %d", w.Code)
	}
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatalf("block: %d %s", w.Code, w.Body.String())
	}
	if w := alice.request("GET", "/", nil); w.Code != 303 {
		t.Fatalf("old session survives: %d", w.Code)
	}
	if signIn(alice, "alice", password) != 401 {
		t.Fatal("blocked login accepted")
	}
	if w := admin.request("GET", "/admin/users", nil); !strings.Contains(w.Body.String(), "Доступ закрыт") {
		t.Fatal("closure not confirmed")
	}
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatalf("unblock: %d %s", w.Code, w.Body.String())
	}
	if w := alice.request("GET", "/", nil); w.Code != 303 {
		t.Fatal("unblock restored old session")
	}
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("unblocked new login failed")
	}
}

func TestBlockDisablesBothModesRevokesCodesAndPreservesOtherOwner(t *testing.T) {
	app, admin, _ := setup(t)
	app.SetGateway(testGateway{})
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	bob := createOrdinary(t, admin, "bob")
	signIn(bob, "bob", password)
	create := func(b *browser, name, mode string) (int64, string) {
		b.request("GET", "/machines", nil)
		w := b.request("POST", "/machines", url.Values{"name": {name}, "mode": {mode}})
		var v struct {
			ID   int64
			Code string
		}
		if err := json.Unmarshal(w.Body.Bytes(), &v); err != nil {
			t.Fatal(err)
		}
		return v.ID, v.Code
	}
	enroll := func(code, key, cred string) int {
		r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(`{"code":"`+code+`","public_key":"`+key+`","credential":"`+cred+`"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		admin.handler.ServeHTTP(w, r)
		return w.Code
	}
	_, code := create(alice, "Agent", "agent")
	credential := strings.Repeat("a", 43)
	if got := enroll(code, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", credential); got != 201 {
		t.Fatal(got)
	}
	p := lifecyclePublication(t, alice, "blocked-agent", "127.0.0.1:8080")
	agentContact(t, alice, credential, `{"ready":true,"applied_generation":1}`)
	_, manual := create(alice, "Manual", "manual")
	if got := enroll(manual, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("m", 43)); got != 201 {
		t.Fatal(got)
	}
	alice.request("GET", "/publications", nil)
	mw := alice.request("POST", "/publications", url.Values{"machine_id": {"2"}, "subdomain": {"blocked-manual"}, "target": {"10.203.0.3:8080"}})
	if mw.Code != 201 {
		t.Fatal(mw.Code, mw.Body.String())
	}
	_, unused := create(alice, "Unused", "agent")
	_, bobCode := create(bob, "Bob", "agent")
	bobCredential := strings.Repeat("b", 43)
	if got := enroll(bobCode, "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", bobCredential); got != 201 {
		t.Fatal(got)
	}
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := agentContact(t, alice, credential, `{"ready":true,"applied_generation":1}`); w.Code != 401 {
		t.Fatalf("blocked agent %d", w.Code)
	}
	if w := agentContact(t, bob, bobCredential, `{"ready":true}`); w.Code != 200 {
		t.Fatalf("other owner %d", w.Code)
	}
	if got := enroll(unused, "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("u", 43)); got != 401 {
		t.Fatalf("old code %d", got)
	}
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if got := signIn(alice, "alice", password); got != 303 {
		t.Fatal(got)
	}
	got := publicationDetail(t, alice, p.ID)
	if got.DesiredEnabled || got.State != "Отключена" || got.URL != p.URL {
		t.Fatalf("publication restored: %+v", got)
	}
	if w := alice.request("POST", "/publications/"+p.ID+"/enable", url.Values{"revision": {"1"}}); w.Code != 409 {
		t.Fatalf("stale intent %d", w.Code)
	}
	if w := alice.request("POST", "/publications/"+p.ID+"/enable", url.Values{"revision": {"2"}}); w.Code != 409 {
		t.Fatalf("machine remains off %d", w.Code)
	}
	if got := enroll(unused, "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("u", 43)); got != 401 {
		t.Fatalf("unblock revived code %d", got)
	}
	if w := alice.request("POST", "/machines/1/enable", url.Values{"revision": {"1"}}); w.Code != 409 {
		t.Fatalf("old machine intent %d", w.Code)
	}
	if w := alice.request("POST", "/machines/1/enable", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatalf("explicit machine enable %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, alice, credential, `{"ready":true,"applied_generation":1}`); w.Code != 200 {
		t.Fatalf("enabled agent %d", w.Code)
	}
	if w := alice.request("POST", "/publications/"+p.ID+"/enable", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatalf("explicit publication enable %d", w.Code)
	}
	if p := publicationDetail(t, alice, p.ID); p.State != "Настраивается" {
		t.Fatal("new agent map not awaited")
	}

}

func TestBlockDoesNotConfirmPendingEnrollmentOrPeerFailureAndResumesAfterRestart(t *testing.T) {
	app, admin, dir := setup(t)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	gateway := &interruptedEnrollmentGateway{failApply: true, failRemove: true, peers: map[int64]tunnel.Peer{}}
	app.SetGateway(gateway)
	code := createEnrollmentCode(t, alice, "Pending")
	if w := enrollmentRequest(alice.handler, context.Background(), code, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("z", 43)); w.Code != 503 {
		t.Fatal(w.Code)
	}
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 503 {
		t.Fatalf("pending peer falsely closed: %d %s", w.Code, w.Body.String())
	}
	if w := admin.request("GET", "/admin/users", nil); strings.Contains(w.Body.String(), "<p>Доступ закрыт</p>") {
		t.Fatal("false confirmed closure")
	}
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 409 {
		t.Fatalf("unblock before cleanup %d", w.Code)
	}
	app.Close()
	reopened, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetGateway(gateway)
	admin.handler = reopened.Handler()
	gateway.failApply = false
	gateway.failRemove = false
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatalf("retry closure %d %s", w.Code, w.Body.String())
	}
	if len(gateway.peers) != 0 {
		t.Fatal("orphan remained")
	}
}

type pausedBlockGateway struct {
	testGateway
	started, release chan struct{}
}

func (g *pausedBlockGateway) ApplyPeer(context.Context, tunnel.Peer) error {
	close(g.started)
	<-g.release
	return nil
}
func TestBlockWaitsForLiveEnrollmentAndOldApplyCannotPromote(t *testing.T) {
	app, admin, dir := setup(t)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	code := createEnrollmentCode(t, alice, "Racing")
	gateway := &pausedBlockGateway{started: make(chan struct{}), release: make(chan struct{})}
	app.SetGateway(gateway)
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	second.SetGateway(gateway)
	otherAdmin := *admin
	otherAdmin.handler = second.Handler()
	done := make(chan int, 1)
	go func() {
		done <- enrollmentRequest(alice.handler, context.Background(), code, "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("v", 43)).Code
	}()
	<-gateway.started
	otherAdmin.request("GET", "/admin/users", nil)
	if w := otherAdmin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 503 {
		close(gateway.release)
		t.Fatalf("live apply falsely closed %d %s", w.Code, w.Body.String())
	}
	if w := otherAdmin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 409 {
		close(gateway.release)
		t.Fatalf("live apply allowed unblock %d", w.Code)
	}
	close(gateway.release)
	if got := <-done; got == 201 {
		t.Fatal("pre-block apply promoted")
	}
	if w := otherAdmin.request("POST", "/admin/users/2/block", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatalf("settled closure %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, alice, strings.Repeat("v", 43), `{"ready":true}`); w.Code != 401 {
		t.Fatal("old credential enabled")
	}
}

func TestPasswordRecoveryDoesNotBypassBlockAndStaleUnblockCannotWin(t *testing.T) {
	_, admin, _ := setup(t)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	if w := alice.request("GET", "/admin/users", nil); w.Code != 403 {
		t.Fatalf("ordinary admin access %d", w.Code)
	}
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/1/block", url.Values{"revision": {"1"}}); w.Code != 404 {
		t.Fatalf("admin can be blocked %d", w.Code)
	}
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	link := resetLink(t, admin, "2")
	anonymous := visitor(t, admin)
	anonymous.request("GET", link, nil)
	if w := anonymous.request("POST", link, url.Values{"password": {newPassword}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if got := signIn(alice, "alice", newPassword); got != 401 {
		t.Fatalf("password reset bypassed block %d", got)
	}
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"1"}}); w.Code != 409 {
		t.Fatalf("stale unblock %d", w.Code)
	}
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if got := signIn(alice, "alice", newPassword); got != 303 {
		t.Fatal(got)
	}
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"3"}}); w.Code != 303 {
		t.Fatal(w.Code)
	}
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 409 {
		t.Fatalf("older unblock overrode newer block %d", w.Code)
	}
}
