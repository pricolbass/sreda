package tunnel_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sreda/internal/tunnel"
)

// memoryKernel models only the root tools' observable state. HTTP is the tested
// boundary; no Linux network isolation is claimed by these tests.
type memoryKernel struct {
	route   string
	key     string
	address string
	allowed bool
	corrupt bool
}

func (k *memoryKernel) Run(_ context.Context, command string, args []string, input string) (string, error) {
	switch {
	case strings.HasSuffix(command, "/ip"):
		return k.route, nil
	case strings.HasSuffix(command, "/wg"):
		if args[0] == "show" {
			if k.key == "" {
				return "", nil
			}
			return k.key + "\t" + k.address + "\n", nil
		}
		if args[4] == "remove" {
			k.key = ""
			k.address = ""
		} else {
			k.key = args[3]
			k.address = args[5]
		}
		return "", nil
	case strings.HasSuffix(command, "/nft"):
		if args[0] == "list" {
			return "", fmt.Errorf("not installed")
		}
		if args[0] == "-j" && args[2] == "table" {
			objects := []any{map[string]any{"table": map[string]any{"family": "inet", "name": "sreda"}}, map[string]any{"set": map[string]any{"family": "inet", "table": "sreda", "name": "clients", "type": "ipv4_addr"}}}
			for _, name := range []string{"input", "forward", "output"} {
				objects = append(objects, map[string]any{"chain": map[string]any{"family": "inet", "table": "sreda", "name": name, "type": "filter", "hook": name, "prio": -10, "policy": "accept"}})
				count := 2
				if k.corrupt && name == "forward" {
					count = 0
				}
				for i := 0; i < count; i++ {
					objects = append(objects, map[string]any{"rule": map[string]any{"family": "inet", "table": "sreda", "chain": name, "expr": []any{map[string]any{"drop": nil}}}})
				}
			}
			b, _ := json.Marshal(map[string]any{"nftables": objects})
			return string(b), nil
		}
		if args[0] == "-j" {
			elems := []string{}
			if k.allowed {
				elems = append(elems, "10.203.0.2")
			}
			b, _ := json.Marshal(map[string]any{"nftables": []any{map[string]any{"set": map[string]any{"name": "clients", "elem": elems}}}})
			return string(b), nil
		}
		if strings.HasPrefix(input, "add element") {
			k.allowed = true
		}
		if strings.HasPrefix(input, "delete element") {
			k.allowed = false
		}
		return "", nil
	}
	return "", fmt.Errorf("unexpected kernel tool")
}
func changePeer(t *testing.T, h http.Handler, action string) int {
	t.Helper()
	r := httptest.NewRequest("POST", "http://localhost/peers/"+action, strings.NewReader(`{"machine_id":1,"public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":"10.203.0.2/32"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w.Code
}
func TestConnectionRequiresDirectWireGuardRoute(t *testing.T) {
	for _, tc := range []struct {
		name, route string
		want        int
	}{
		{"missing", "[]", 503},
		{"internet default", `[{"dst":"10.203.0.2","gateway":"192.0.2.1","dev":"eth0"}]`, 503},
		{"via another gateway", `[{"dst":"10.203.0.2","gateway":"10.203.0.99","dev":"wg-sreda"}]`, 503},
		{"direct tunnel", `[{"dst":"10.203.0.2","dev":"wg-sreda","prefsrc":"10.203.0.1"}]`, 204},
	} {
		t.Run(tc.name, func(t *testing.T) {
			k := &memoryKernel{route: tc.route}
			h, err := tunnel.NewHelper(tunnel.HelperConfig{Interface: "wg-sreda", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft"}, k)
			if err != nil {
				t.Fatal(err)
			}
			if got := changePeer(t, h, "apply"); got != tc.want {
				t.Fatalf("connection status=%d, want %d", got, tc.want)
			}
			if tc.want != 204 && k.allowed {
				t.Fatal("unroutable connection was opened")
			}
		})
	}
}

func TestConnectionDoesNotConfirmMissingIsolationRules(t *testing.T) {
	k := &memoryKernel{route: `[{"dst":"10.203.0.2","dev":"wg-sreda"}]`}
	h, err := tunnel.NewHelper(tunnel.HelperConfig{Interface: "wg-sreda", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft"}, k)
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Initialize(context.Background()); err != nil {
		t.Fatal(err)
	}
	k.corrupt = true
	if got := changePeer(t, h, "apply"); got != 503 {
		t.Fatalf("connection with missing isolation rules status=%d", got)
	}
}

func TestConnectionAddressIsIndependentOfMonotonicMachineID(t *testing.T) {
	k := &memoryKernel{route: `[{"dst":"10.203.0.2","dev":"wg-sreda"}]`}
	h, err := tunnel.NewHelper(tunnel.HelperConfig{Interface: "wg-sreda", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft"}, k)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://localhost/peers/apply", strings.NewReader(`{"machine_id":101,"public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":"10.203.0.2/32"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 204 {
		t.Fatalf("available address rejected for later machine id: %d", w.Code)
	}
}
