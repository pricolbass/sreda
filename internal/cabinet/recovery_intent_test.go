package cabinet_test

import (
	"context"
	"net/url"
	"sreda/internal/cabinet"
	"sreda/internal/tunnel"
	"strings"
	"sync"
	"testing"
	"time"
)

type pausedRecoveryApplyGateway struct {
	testGateway
	once             sync.Once
	started, release chan struct{}
}

func (g *pausedRecoveryApplyGateway) ApplyPeer(ctx context.Context, peer tunnel.Peer) error {
	if peer.MachineID == 1 {
		g.once.Do(func() { close(g.started) })
		select {
		case <-g.release:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

func TestRecoveryCannotOverrideNewerOwnerEnableFromAnotherApplication(t *testing.T) {
	app, b, dir := setup(t)
	app.SetGateway(testGateway{})
	b.login()
	enrolledMachine(t, b)
	code := createEnrollmentCode(t, b, "Second machine")
	credential := strings.Repeat("s", 43)
	if w := enrollmentRequest(b.handler, context.Background(), code, "AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", credential); w.Code != 201 {
		t.Fatal(w.Code, w.Body.String())
	}
	b.request("GET", "/machines", nil)
	if w := b.request("POST", "/machines/2/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	gateway := &pausedRecoveryApplyGateway{started: make(chan struct{}), release: make(chan struct{})}
	app.SetGateway(gateway)
	second.SetGateway(gateway)
	var releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gateway.release) }) }
	defer release()
	finished := make(chan error, 1)
	go func() { finished <- app.ReconcileMachinePeers(context.Background()) }()
	select {
	case <-gateway.started:
	case <-time.After(3 * time.Second):
		t.Fatal("recovery did not reach first peer")
	}
	// The recovery pass has captured both machines. Another application now
	// commits and confirms a newer owner command for the second machine.
	b.handler = second.Handler()
	b.request("GET", "/machines", nil)
	if w := b.request("POST", "/machines/2/enable", url.Values{"revision": {"2"}}); w.Code != 303 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := agentContact(t, b, credential, `{"ready":true}`); w.Code != 200 {
		t.Fatalf("owner enable not confirmed: %d %s", w.Code, w.Body.String())
	}
	release()
	if err := <-finished; err != nil {
		t.Fatal(err)
	}
	if w := agentContact(t, b, credential, `{"ready":true}`); w.Code != 200 {
		t.Fatalf("stale recovery disabled newly enabled connection: %d %s", w.Code, w.Body.String())
	}
	page := b.request("GET", "/machines", nil)
	if strings.Contains(page.Body.String(), `/machines/2/enable`) || !strings.Contains(page.Body.String(), `/machines/2/disable`) {
		t.Fatal("recovery replaced owner's enabled intent")
	}
}
