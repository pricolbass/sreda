package cabinet_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"sreda/internal/tunnel"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestServerRecoveryRestoresHealthyOwnerAfterSlowUnfinishedBlock(t *testing.T) {
	app, admin, dir := setup(t)
	app.SetGateway(testGateway{})
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("blocked owner initial login failed")
	}
	blockedCredential := enrolledMachine(t, alice)
	for _, enrollment := range []struct{ key, credential string }{
		{"AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("a", 43)},
		{"AwAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", strings.Repeat("c", 43)},
	} {
		code := createEnrollmentCode(t, alice, "Another blocked machine")
		if w := enrollmentRequest(alice.handler, context.Background(), code, enrollment.key, enrollment.credential); w.Code != 201 {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	bob := createOrdinary(t, admin, "bob")
	if signIn(bob, "bob", password) != 303 {
		t.Fatal("healthy owner initial login failed")
	}
	code := createEnrollmentCode(t, bob, "Healthy machine")
	healthyCredential := strings.Repeat("b", 43)
	if w := enrollmentRequest(bob.handler, context.Background(), code, "BAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", healthyCredential); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	failed := &removalGateway{}
	failed.fail.Store(true)
	app.SetGateway(failed)
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); w.Code != 503 {
		t.Fatal(w.Code, w.Body.String())
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}

	// The actual CLI starts with an empty helper. Three slow revocation failures
	// exceed its former shared 20s pass deadline, while each remains below the
	// existing 10s operation and 30s independent peer-cleanup limits. Later
	// failures are immediate, allowing this test to isolate coordinator fairness.
	var removals atomic.Int32
	healthyApplied := make(chan struct{}, 1)
	handler, stop := recoveryServerProcess(t, dir, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var peer tunnel.Peer
		if err := json.NewDecoder(r.Body).Decode(&peer); err != nil {
			http.Error(w, "invalid peer", 400)
			return
		}
		switch r.URL.Path {
		case "/peers/remove":
			if removals.Add(1) <= 3 {
				timer := time.NewTimer(7 * time.Second)
				defer timer.Stop()
				select {
				case <-timer.C:
				case <-r.Context().Done():
					return
				}
			}
			http.Error(w, "revocation remains unconfirmed", 503)
		case "/peers/apply":
			if peer.MachineID == 4 {
				select {
				case healthyApplied <- struct{}{}:
				default:
				}
			}
			w.WriteHeader(204)
		default:
			http.NotFound(w, r)
		}
	}), 75*time.Second)
	defer stop()
	select {
	case <-healthyApplied:
	default:
		t.Fatal("unfinished block exhausted startup recovery before the healthy peer was restored")
	}
	admin.handler, alice.handler, bob.handler = handler, handler, handler
	if w := agentContact(t, bob, healthyCredential, `{"ready":true}`); w.Code != 200 {
		t.Fatalf("healthy owner's connection unavailable: %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, alice, blockedCredential, `{"ready":true}`); w.Code != 401 {
		t.Fatal("recovery revived blocked owner's connection")
	}
	admin.request("GET", "/admin/users", nil)
	if w := admin.request("POST", "/admin/users/2/unblock", url.Values{"revision": {"2"}}); w.Code != 409 {
		t.Fatalf("unconfirmed closure permitted unblock: %d %s", w.Code, w.Body.String())
	}
}
