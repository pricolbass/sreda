package cabinet_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
)

type interruptedEnrollmentGateway struct {
	testGateway
	mu              sync.Mutex
	cancel          context.CancelFunc
	failRemove      bool
	failApply       bool
	cleanupCanceled bool
	peers           map[int64]tunnel.Peer
	applyCount      map[int64]int
	removeCount     map[int64]int
}

func (g *interruptedEnrollmentGateway) ApplyPeer(ctx context.Context, peer tunnel.Peer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.peers[peer.MachineID] = peer
	if g.applyCount == nil {
		g.applyCount = map[int64]int{}
	}
	g.applyCount[peer.MachineID]++
	if g.cancel != nil {
		g.cancel()
		g.cancel = nil
	}
	if g.failApply {
		return errors.New("helper failed after a possible partial apply")
	}
	return nil
}
func (g *interruptedEnrollmentGateway) RemovePeer(ctx context.Context, peer tunnel.Peer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.cleanupCanceled = ctx.Err() != nil
	if g.removeCount == nil {
		g.removeCount = map[int64]int{}
	}
	g.removeCount[peer.MachineID]++
	if g.failRemove {
		return errors.New("helper cannot confirm peer removal")
	}
	delete(g.peers, peer.MachineID)
	return nil
}
func createEnrollmentCode(t *testing.T, b *browser, name string) string {
	t.Helper()
	b.request("GET", "/machines", nil)
	w := b.request("POST", "/machines", url.Values{"name": {name}})
	if w.Code != 201 {
		t.Fatalf("create machine: %d %s", w.Code, w.Body.String())
	}
	var value struct {
		Code string `json:"code"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value.Code
}
func enrollmentRequest(handler http.Handler, ctx context.Context, code, key, credential string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"code": code, "public_key": key, "credential": credential})
	r := httptest.NewRequest("POST", origin+"/api/agent/enroll", strings.NewReader(string(body))).WithContext(ctx)
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	return w
}
func TestFailedEnrollmentCompensationIsDurableAcrossRestart(t *testing.T) {
	app, b, dir := setup(t)
	b.login()
	code := createEnrollmentCode(t, b, "Interrupted machine")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gateway := &interruptedEnrollmentGateway{cancel: cancel, failRemove: true, peers: map[int64]tunnel.Peer{}}
	app.SetGateway(gateway)
	key := "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	credential := strings.Repeat("d", 43)
	if w := enrollmentRequest(b.handler, ctx, code, key, credential); w.Code == 201 {
		t.Fatal("canceled persistence reported success")
	}
	if gateway.cleanupCanceled {
		t.Fatal("compensation reused canceled HTTP context")
	}
	app.Close()
	reopened, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	reopened.SetGateway(gateway)
	b.handler = reopened.Handler()
	request := httptest.NewRequest("POST", origin+"/api/agent/heartbeat", strings.NewReader(`{"ready":true}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer "+credential)
	response := httptest.NewRecorder()
	b.handler.ServeHTTP(response, request)
	if response.Code != 401 {
		t.Fatalf("unfinished enrollment authenticated agent: %d %s", response.Code, response.Body.String())
	}
	if w := enrollmentRequest(b.handler, context.Background(), code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("e", 43)); w.Code != 401 {
		t.Fatalf("unfinished code rebound to another identity: %d %s", w.Code, w.Body.String())
	}
	second := createEnrollmentCode(t, b, "Independent machine")
	if w := enrollmentRequest(b.handler, context.Background(), second, key, strings.Repeat("e", 43)); w.Code != 400 {
		t.Fatalf("pending peer key was not reserved: %d %s", w.Code, w.Body.String())
	}

	if w := enrollmentRequest(b.handler, context.Background(), second, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("e", 43)); w.Code != 201 {
		t.Fatalf("independent enrollment: %d %s", w.Code, w.Body.String())
	}
	if gateway.peers[1].Address == gateway.peers[2].Address {
		t.Fatal("unconfirmed orphan address was reused")
	}
	independentApplications := gateway.applyCount[2]
	if err := reopened.ReconcileMachinePeers(context.Background()); err == nil {
		t.Fatal("unconfirmed cleanup reported success")
	}
	if gateway.applyCount[2] <= independentApplications {
		t.Fatal("cleanup failure prevented independent peer reconciliation")
	}
	gateway.failRemove = false
	if err := reopened.ReconcileMachinePeers(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, exists := gateway.peers[1]; exists {
		t.Fatal("orphan peer survived reconciliation")
	}
	if _, exists := gateway.peers[2]; !exists {
		t.Fatal("independent peer was not restored")
	}
	if w := enrollmentRequest(b.handler, context.Background(), code, key, credential); w.Code != 201 {
		t.Fatalf("original client cannot retry after confirmed cleanup: %d %s", w.Code, w.Body.String())
	}
}

func TestSameClientResumesFailedEnrollmentOnlyAfterConfirmedCleanup(t *testing.T) {
	app, b, _ := setup(t)
	b.login()
	code := createEnrollmentCode(t, b, "Retry partial apply")
	gateway := &interruptedEnrollmentGateway{failApply: true, failRemove: true, peers: map[int64]tunnel.Peer{}}
	app.SetGateway(gateway)
	key := "AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	credential := strings.Repeat("f", 43)
	if w := enrollmentRequest(b.handler, context.Background(), code, key, credential); w.Code != 503 {
		t.Fatalf("ambiguous apply: %d", w.Code)
	}
	gateway.failApply = false
	if w := enrollmentRequest(b.handler, context.Background(), code, key, credential); w.Code != 503 {
		t.Fatalf("unconfirmed removal allowed retry: %d", w.Code)
	}
	if gateway.applyCount[1] != 1 {
		t.Fatal("retry applied before cleanup confirmation")
	}
	if w := enrollmentRequest(b.handler, context.Background(), code, key, strings.Repeat("g", 43)); w.Code != 401 {
		t.Fatalf("changed credential rebound code: %d", w.Code)
	}
	gateway.failRemove = false
	if w := enrollmentRequest(b.handler, context.Background(), code, key, credential); w.Code != 201 {
		t.Fatalf("same-client resume: %d %s", w.Code, w.Body.String())
	}
	if gateway.applyCount[1] != 2 {
		t.Fatal("successful resume did not apply once")
	}
	if w := enrollmentRequest(b.handler, context.Background(), code, key, credential); w.Code != 401 {
		t.Fatalf("completed code reused: %d", w.Code)
	}
}

func TestPendingCleanupRotatesInsteadOfStarvingOtherMachines(t *testing.T) {
	app, b, _ := setup(t)
	b.login()
	gateway := &interruptedEnrollmentGateway{failApply: true, failRemove: true, peers: map[int64]tunnel.Peer{}}
	app.SetGateway(gateway)
	keys := []string{"AQAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="}
	for i, key := range keys {
		code := createEnrollmentCode(t, b, "Pending cleanup")
		if w := enrollmentRequest(b.handler, context.Background(), code, key, strings.Repeat(string(rune('h'+i)), 43)); w.Code != 503 {
			t.Fatalf("partial apply: %d", w.Code)
		}
	}
	if err := app.ReconcileMachinePeers(context.Background()); err == nil {
		t.Fatal("failed cleanup reported success")
	}
	if gateway.removeCount[3] != 1 {
		t.Fatal("first pass did not bound pending cleanup work")
	}
	if err := app.ReconcileMachinePeers(context.Background()); err == nil {
		t.Fatal("failed cleanup reported success")
	}
	if gateway.removeCount[3] != 2 {
		t.Fatal("earlier cleanup failures permanently starved the third machine")
	}
	for _, peer := range gateway.peers {
		if peer.Address == "" {
			t.Fatal("pending peer lost its reservation")
		}
	}
}
