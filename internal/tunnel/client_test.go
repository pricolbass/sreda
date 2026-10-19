package tunnel_test

import (
	"context"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"sreda/internal/tunnel"
	"testing"
)

func TestClientTreatsTimeoutOrUnexpectedResponseAsUnconfirmed(t *testing.T) {
	for _, status := range []int{200, 202, 400, 503} {
		dir, err := os.MkdirTemp("/tmp", "sreda-net-")
		if err != nil {
			t.Fatal(err)
		}
		socket := filepath.Join(dir, "net.sock")
		listener, err := net.Listen("unix", socket)
		if err != nil {
			t.Fatal(err)
		}
		server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) })}
		go server.Serve(listener)
		c := tunnel.NewClient(socket, tunnel.Details{})
		err = c.RemovePeer(context.Background(), tunnel.Peer{MachineID: 1, PublicKey: "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=", Address: "10.203.0.2/32"})
		server.Close()
		os.RemoveAll(dir)
		if err == nil {
			t.Fatalf("unconfirmed status %d reported success", status)
		}
	}
}
