package cabinet_test

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"sreda/internal/agent"
	"sreda/internal/agentprotocol"
	"sreda/internal/publication"
	"sreda/internal/tunnel"
)

// This fixture replaces the external WireGuard/kernel boundary. It does not
// model packet isolation, kernel resource use, or a Debian/LXC machine.
type functionalPoolGateway struct {
	testGateway
	mu    sync.Mutex
	peers map[int64]tunnel.Peer
}

func (g *functionalPoolGateway) ApplyPeer(_ context.Context, peer tunnel.Peer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.peers[peer.MachineID] = peer
	return nil
}
func (g *functionalPoolGateway) RemovePeer(_ context.Context, peer tunnel.Peer) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	delete(g.peers, peer.MachineID)
	return nil
}
func (g *functionalPoolGateway) LatestHandshake(_ context.Context, peer tunnel.Peer) (time.Time, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if g.peers[peer.MachineID] != peer {
		return time.Time{}, errors.New("fixture peer disabled")
	}
	return time.Now(), nil
}
func (g *functionalPoolGateway) active(address string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	for _, peer := range g.peers {
		if strings.TrimSuffix(peer.Address, "/32") == address {
			return true
		}
	}
	return false
}
func (g *functionalPoolGateway) count() int { g.mu.Lock(); defer g.mu.Unlock(); return len(g.peers) }

type functionalPublication struct {
	publication.Publication
	ownerIndex int
	body       string
}

// TestFunctionalHundredConnectionsAndTwoHundredPublications is a correctness
// check of the logical address pool and delivery. It is not a load benchmark:
// there are no real WireGuard peers, LXC namespaces, or throughput measurements.
func TestFunctionalHundredConnectionsAndTwoHundredPublications(t *testing.T) {
	started := time.Now()
	app, admin, _ := setup(t)
	network := &functionalPoolGateway{peers: map[int64]tunnel.Peer{}}
	app.SetGateway(network)
	if err := app.ConfigurePublicationZone("example.test"); err != nil {
		t.Fatal(err)
	}
	admin.login()
	owners := []*browser{createOrdinary(t, admin, "alice"), createOrdinary(t, admin, "bob")}
	for i, name := range []string{"alice", "bob"} {
		if got := signIn(owners[i], name, password); got != 303 {
			t.Fatalf("owner login %d", got)
		}
	}
	destinations := map[string]string{}
	app.SetPublicationDialer(func(ctx context.Context, kind, address string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(address)
		if err != nil || !network.active(host) {
			return nil, errors.New("fixture tunnel peer unavailable")
		}
		target, ok := destinations[address]
		if !ok {
			return nil, errors.New("unregistered fixture destination")
		}
		return (&net.Dialer{}).DialContext(ctx, kind, target)
	})
	pubs := make([]functionalPublication, 0, 200)
	credentials := make([]string, 100)
	addresses := map[string]bool{}
	machineIDs := map[int64]bool{}
	for i := range 100 {
		ownerIndex := i % 2
		owner := owners[ownerIndex]
		mode := "agent"
		if i >= 80 {
			mode = "manual"
		}
		owner.request("GET", "/machines", nil)
		created := owner.request("POST", "/machines", url.Values{"name": {fmt.Sprintf("logical-%03d", i+1)}, "mode": {mode}})
		if created.Code != 201 {
			t.Fatalf("machine %d create: %d %s", i+1, created.Code, created.Body.String())
		}
		var pending struct {
			ID   int64
			Code string
		}
		if err := json.Unmarshal(created.Body.Bytes(), &pending); err != nil {
			t.Fatal(err)
		}
		if machineIDs[pending.ID] {
			t.Fatal("machine identity reused")
		}
		machineIDs[pending.ID] = true
		private, err := ecdh.X25519().GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		var secret [32]byte
		if _, err := rand.Read(secret[:]); err != nil {
			t.Fatal(err)
		}
		credentials[i] = base64.RawURLEncoding.EncodeToString(secret[:])
		key := base64.StdEncoding.EncodeToString(private.PublicKey().Bytes())
		response := enrollmentRequest(owner.handler, context.Background(), pending.Code, key, credentials[i])
		if response.Code != 201 {
			t.Fatalf("machine %d enroll: %d %s", i+1, response.Code, response.Body.String())
		}
		var control agentprotocol.Control
		if err := json.Unmarshal(response.Body.Bytes(), &control); err != nil {
			t.Fatal(err)
		}
		if control.MachineID != pending.ID || addresses[control.Address] {
			t.Fatalf("wrong or reused connection: machine=%d address=%s", control.MachineID, control.Address)
		}
		addresses[control.Address] = true
		ip := strings.TrimSuffix(control.Address, "/32")
		var proxy *agent.Proxy
		if mode == "agent" {
			proxy = agent.NewProxy("127.0.0.1")
			t.Cleanup(proxy.Close)
			server := httptest.NewServer(proxy)
			t.Cleanup(server.Close)
			destinations[net.JoinHostPort(ip, "9080")] = server.Listener.Addr().String()
		} else if control.ProxyToken != "" {
			t.Fatal("manual connection received agent proxy credential")
		}
		for appIndex := range 2 {
			var marker atomic.Value
			marker.Store("fixture not configured")
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				io.WriteString(w, marker.Load().(string))
			}))
			t.Cleanup(server.Close)
			target := server.Listener.Addr().String()
			if mode == "manual" {
				_, port, err := net.SplitHostPort(target)
				if err != nil {
					t.Fatal(err)
				}
				logical := net.JoinHostPort(ip, port)
				destinations[logical] = target
				target = logical
			}
			owner.request("GET", "/publications", nil)
			response := owner.request("POST", "/publications", url.Values{"machine_id": {strconv.FormatInt(pending.ID, 10)}, "subdomain": {fmt.Sprintf("machine-%03d-app-%d", i+1, appIndex+1)}, "target": {target}})
			if response.Code != 201 {
				t.Fatalf("publication %d/%d: %d %s", i+1, appIndex+1, response.Code, response.Body.String())
			}
			var p publication.Publication
			if err := json.Unmarshal(response.Body.Bytes(), &p); err != nil {
				t.Fatal(err)
			}
			body := fmt.Sprintf("owner=%s machine=%d application=%d publication=%s", []string{"alice", "bob"}[ownerIndex], pending.ID, appIndex+1, p.ID)
			marker.Store(body)
			pubs = append(pubs, functionalPublication{p, ownerIndex, body})
		}
		if proxy != nil {
			response := agentContact(t, owner, credentials[i], `{"ready":true}`)
			if response.Code != 200 {
				t.Fatalf("control %d: %d", i+1, response.Code)
			}
			if err := json.Unmarshal(response.Body.Bytes(), &control); err != nil {
				t.Fatal(err)
			}
			if len(control.Routes) != 2 {
				t.Fatalf("machine %d did not reuse its connection for two routes", i+1)
			}
			if err := proxy.ApplyControl(control); err != nil {
				t.Fatal(err)
			}
			ack := fmt.Sprintf(`{"ready":true,"applied_generation":%d}`, control.Generation)
			if w := agentContact(t, owner, credentials[i], ack); w.Code != 200 {
				t.Fatalf("ack %d: %d", i+1, w.Code)
			}
		} else if w := agentContact(t, owner, credentials[i], `{"ready":true}`); w.Code != 401 {
			t.Fatalf("manual credential authenticated agent: %d", w.Code)
		}
	}
	if network.count() != 100 || len(addresses) != 100 || len(pubs) != 200 {
		t.Fatalf("logical fixture incomplete: peers=%d addresses=%d publications=%d", network.count(), len(addresses), len(pubs))
	}
	// A distinct 101st machine may be recorded, but it must not receive a peer.
	code := createEnrollmentCode(t, owners[0], "Pool exhausted")
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var extra [32]byte
	if _, err := rand.Read(extra[:]); err != nil {
		t.Fatal(err)
	}
	response := enrollmentRequest(owners[0].handler, context.Background(), code, base64.StdEncoding.EncodeToString(private.PublicKey().Bytes()), base64.RawURLEncoding.EncodeToString(extra[:]))
	if response.Code != 503 || !strings.Contains(response.Body.String(), "Исчерпан пул") {
		t.Fatalf("101st connection: %d %s", response.Code, response.Body.String())
	}
	if network.count() != 100 {
		t.Fatal("101st enrollment changed existing peer allocation")
	}
	var client *http.Client
	var localURL string
	if os.Getenv("SREDA_TEST_CADDY") != "" {
		client, _ = caddyClient(t, app.Handler())
		t.Log("delivery boundary: actual local Caddy, wildcard local CA, Unix socket")
	} else {
		server := httptest.NewTLSServer(app.Handler())
		t.Cleanup(server.Close)
		client = server.Client()
		localURL = server.URL
		t.Log("delivery boundary: local HTTPS server; actual Caddy not requested")
	}
	check := func(blocked bool) {
		t.Helper()
		for _, p := range pubs {
			address := p.URL + "/functional-identity"
			if localURL != "" {
				address = localURL + "/functional-identity"
			}
			request, err := http.NewRequest("GET", address, nil)
			if err != nil {
				t.Fatal(err)
			}
			publicURL, err := url.Parse(p.URL)
			if err != nil {
				t.Fatal(err)
			}
			request.Host = publicURL.Host
			result, err := client.Do(request)
			if err != nil {
				t.Fatalf("%s delivery: %v", p.Subdomain, err)
			}
			body, err := io.ReadAll(result.Body)
			result.Body.Close()
			if err != nil {
				t.Fatal(err)
			}
			if blocked && p.ownerIndex == 0 {
				if result.StatusCode != 404 {
					t.Fatalf("blocked publication %s: %d", p.Subdomain, result.StatusCode)
				}
			} else if result.StatusCode != 200 || string(body) != p.body {
				t.Fatalf("wrong delivery for %s: %d %q, expected %q", p.Subdomain, result.StatusCode, body, p.body)
			}
		}
	}
	check(false)
	admin.request("GET", "/admin/users", nil)
	if response := admin.request("POST", "/admin/users/2/block", url.Values{"revision": {"1"}}); response.Code != 303 {
		t.Fatalf("owner block: %d %s", response.Code, response.Body.String())
	}
	if network.count() != 50 {
		t.Fatalf("block removed wrong peer set: %d", network.count())
	}
	check(true)
	for i := 0; i < 80; i++ {
		want := 200
		if i%2 == 0 {
			want = 401
		}
		if response := agentContact(t, owners[i%2], credentials[i], `{"ready":true}`); response.Code != want {
			t.Fatalf("agent %d after owner block: %d, expected %d", i+1, response.Code, want)
		}
	}
	t.Logf("PARTIAL correctness only: 100 logical connections (80 agent/20 manual), 200 publication identities, 101st rejected, one owner blocked; elapsed %s. No LXC/kernel/capacity measurement.", time.Since(started).Round(time.Millisecond))
}
