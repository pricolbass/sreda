package cabinet_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestReconciliationResumesFailedUserClosureAfterRestartWithoutAnotherAdministratorCommand(t *testing.T) {
	app, admin, dir := setup(t)
	gateway := &removalGateway{}
	app.SetGateway(gateway)
	app.ConfigurePublicationZone("example.test")
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	credential := enrolledMachine(t, alice)
	p := lifecyclePublication(t, alice, "recover-block", "127.0.0.1:8080")
	agentContact(t, alice, credential, `{"ready":true,"applied_generation":1}`)
	bob := createOrdinary(t, admin, "bob")
	signIn(bob, "bob", password)
	bobCredential := strings.Repeat("b", 43)
	bobCode := createEnrollmentCode(t, bob, "Other owner")
	if w := enrollmentRequest(bob.handler, context.Background(), bobCode, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", bobCredential); w.Code != 201 {
		t.Fatal(w.Code)
	}
	bob.request("GET", "/publications", nil)
	other := bob.request("POST", "/publications", url.Values{"machine_id": {"2"}, "subdomain": {"restore-other"}, "target": {"127.0.0.1:8080"}})
	if other.Code != 201 {
		t.Fatal(other.Code, other.Body.String())
	}
	var otherPublication struct{ ID string }
	json.Unmarshal(other.Body.Bytes(), &otherPublication)
	agentContact(t, bob, bobCredential, `{"ready":true,"applied_generation":1}`)
	gateway.fail.Store(true)
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 503 {
		t.Fatalf("failed cleanup: %d %s", w.Code, w.Body.String())
	}
	app.Close()
	handler, stop := recoveryServerProcess(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/peers/remove" && r.URL.Path != "/peers/apply" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(204)
	}))
	defer stop()
	admin.handler = handler
	alice.handler = handler
	bob.handler = handler
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if strings.Contains(admin.request("GET", "/admin/users", nil).Body.String(), "<p>Доступ закрыт</p>") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if w := agentContact(t, bob, bobCredential, `{"ready":true,"applied_generation":1}`); w.Code != 200 {
		t.Fatalf("other owner altered by recovery: %d %s", w.Code, w.Body.String())
	}
	if got := publicationDetail(t, bob, otherPublication.ID); !got.DesiredEnabled || got.State != "Настроена" {
		t.Fatalf("other publication altered: %+v", got)
	}
	page := admin.request("GET", "/admin/users", nil)
	if !strings.Contains(page.Body.String(), "<p>Доступ закрыт</p>") {
		t.Fatalf("pending block not resumed: %s", page.Body.String())
	}
	if w := agentContact(t, alice, credential, `{"ready":true,"applied_generation":1}`); w.Code != 401 {
		t.Fatal("blocked credential restored")
	}
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("new login refused")
	}
	if got := publicationDetail(t, alice, p.ID); got.DesiredEnabled || got.State != "Отключена" || got.URL != p.URL {
		t.Fatalf("resources reopened: %+v", got)
	}
}

func TestRoutinePeerRestorationDoesNotRevokeAnAlreadyVerifiedAgent(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	b.login()
	credential := enrolledMachine(t, b)
	gateway := &pausedBlockGateway{started: make(chan struct{}), release: make(chan struct{})}
	app.SetGateway(gateway)
	done := make(chan error, 1)
	go func() { done <- app.ReconcileMachinePeers(context.Background()) }()
	<-gateway.started
	response := agentContact(t, b, credential, `{"ready":true}`)
	close(gateway.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if response.Code != 200 {
		t.Fatalf("routine restore revoked running agent: %d %s", response.Code, response.Body.String())
	}
}

type recoveryGateway struct {
	testGateway
	mu        sync.Mutex
	peers     map[int64]tunnel.Peer
	failFirst bool
	cancel    context.CancelFunc
}

func (g *recoveryGateway) ApplyPeer(_ context.Context, p tunnel.Peer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	if p.MachineID == 1 && g.failFirst {
		g.cancel()
		return errors.New("fixture: early peer exhausted pass")
	}
	g.peers[p.MachineID] = p
	return nil
}
func (g *recoveryGateway) RemovePeer(_ context.Context, p tunnel.Peer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.peers, p.MachineID)
	return nil
}
func TestRestorationContinuesPastAnUnavailableEarlierMachineAndRetainsDesiredIntent(t *testing.T) {
	app, b, _ := setup(t)
	app.SetGateway(testGateway{})
	app.ConfigurePublicationZone("example.test")
	b.login()
	firstCredential := enrolledMachine(t, b)
	code := createEnrollmentCode(t, b, "Second")
	secondCredential := strings.Repeat("s", 43)
	if w := enrollmentRequest(b.handler, context.Background(), code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", secondCredential); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	p := lifecyclePublication(t, b, "restore-intent", "127.0.0.1:8080")
	gateway := &recoveryGateway{peers: map[int64]tunnel.Peer{}, failFirst: true}
	app.SetGateway(gateway)
	for i := 0; i < 2; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		gateway.cancel = cancel
		if err := app.ReconcileMachinePeers(ctx); err == nil {
			t.Fatal("fixture failure not surfaced")
		}
		cancel()
	}
	gateway.mu.Lock()
	_, secondRestored := gateway.peers[2]
	gateway.failFirst = false
	gateway.mu.Unlock()
	if !secondRestored {
		t.Fatal("unavailable first machine starved second machine across restoration passes")
	}
	if err := app.ReconcileMachinePeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w := agentContact(t, b, firstCredential, `{"ready":true,"applied_generation":1}`); w.Code != 200 {
		t.Fatalf("desired enabled intent lost: %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, b, secondCredential, `{"ready":true}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if got := publicationDetail(t, b, p.ID); got.URL != p.URL || !got.DesiredEnabled {
		t.Fatalf("publication changed: %+v", got)
	}
}

type pausedRemovalRecoveryGateway struct {
	testGateway
	once             sync.Once
	started, release chan struct{}
}

func (g *pausedRemovalRecoveryGateway) RemovePeer(ctx context.Context, _ tunnel.Peer) error {
	var interrupted error
	g.once.Do(func() {
		close(g.started)
		select {
		case <-g.release:
		case <-ctx.Done():
			interrupted = ctx.Err()
		}
	})
	return interrupted
}
func TestBackgroundClosureLeasePreventsConcurrentRetryFromConfirmingAndUnblockingEarly(t *testing.T) {
	app, admin, dir := setup(t)
	gateway := &removalGateway{}
	app.SetGateway(gateway)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	signIn(alice, "alice", password)
	credential := enrolledMachine(t, alice)
	gateway.fail.Store(true)
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 503 {
		t.Fatal(w.Code)
	}
	resumed, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer resumed.Close()
	paused := &pausedRemovalRecoveryGateway{started: make(chan struct{}), release: make(chan struct{})}
	resumed.SetGateway(paused)
	done := make(chan error, 1)
	go func() { done <- resumed.ReconcileMachinePeers(context.Background()) }()
	<-paused.started
	gateway.fail.Store(false)
	retry := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"2"}})
	unblock := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}})
	close(paused.release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if retry.Code != 409 || unblock.Code != 409 {
		t.Fatalf("unfinished worker allowed early confirmation: retry%d unblock%d", retry.Code, unblock.Code)
	}
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("login")
	}
	if w := alice.request("POST", "/machines/1/enable", url.Values{"revision": {"3"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := resumed.ReconcileMachinePeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if w := agentContact(t, alice, credential, `{"ready":true}`); w.Code != 200 {
		t.Fatalf("old closure affected explicitly restored access: %d %s", w.Code, w.Body.String())
	}
}
