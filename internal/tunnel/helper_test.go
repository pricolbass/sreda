package tunnel_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"sreda/internal/tunnel"
)

// No Linux network commands run on the macOS test host. The unavailable kernel
// boundary proves that unconfirmed changes cannot be reported as successful.
type unavailableKernel struct{}

func (unavailableKernel) Run(context.Context, string, []string, string) (string, error) {
	return "", errors.New("kernel unavailable")
}

func TestHelperDoesNotConfirmUnappliedPeer(t *testing.T) {
	h, err := tunnel.NewHelper(tunnel.HelperConfig{Interface: "wg-sreda", WG: "/usr/bin/wg", NFT: "/usr/sbin/nft"}, unavailableKernel{})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "http://localhost/peers/apply", strings.NewReader(`{"machine_id":1,"public_key":"AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=","address":"10.203.0.2/32"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != http.StatusServiceUnavailable {
		t.Fatalf("unconfirmed change: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "kernel unavailable") {
		t.Fatal("raw command error exposed")
	}
}
