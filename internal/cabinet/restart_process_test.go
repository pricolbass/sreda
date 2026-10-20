package cabinet_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sreda/internal/command"
	"syscall"
	"testing"
	"time"
)

func TestRecoveryServerChild(t *testing.T) {
	if os.Getenv("SREDA_RECOVERY_CHILD") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			if err := command.Run(os.Args[i+1:], os.Stdin, os.Stdout, os.Stderr); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
			os.Exit(0)
		}
	}
	os.Exit(2)
}

// The child runs the production CLI and restoration loop. Only the external
// privileged helper is replaced with a local Unix HTTP endpoint.
func recoveryServerProcess(t *testing.T, dataDir string, helper http.Handler) (http.Handler, func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "srrec-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	helperPath := filepath.Join(dir, "helper.sock")
	listener, err := net.Listen("unix", helperPath)
	if err != nil {
		t.Fatal(err)
	}
	helperServer := &http.Server{Handler: helper}
	go helperServer.Serve(listener)
	t.Cleanup(func() { helperServer.Close() })
	socket := filepath.Join(dir, "cabinet.sock")
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	child := exec.Command(binary, "-test.run=^TestRecoveryServerChild$", "--", "serve", "--data-dir", dataDir, "--socket", socket)
	child.Env = append(os.Environ(), "SREDA_RECOVERY_CHILD=1", "SREDA_NETWORK_SOCKET="+helperPath, "SREDA_WG_PUBLIC_KEY=AgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "SREDA_WG_ENDPOINT=wg.example.test:51820")
	log, err := os.Create(filepath.Join(dir, "server.log"))
	if err != nil {
		t.Fatal(err)
	}
	child.Stdout = log
	child.Stderr = log
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	stopped := false
	stop := func() {
		if stopped {
			return
		}
		stopped = true
		child.Process.Signal(syscall.SIGTERM)
		done := make(chan error, 1)
		go func() { done <- child.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("recovery child exit: %v", err)
			}
		case <-time.After(15 * time.Second):
			child.Process.Kill()
			<-done
			t.Error("recovery child did not stop")
		}
		transport.CloseIdleConnections()
		log.Close()
	}
	t.Cleanup(stop)
	forwarding := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := r.Clone(r.Context())
		request.RequestURI = ""
		request.URL.Scheme = "http"
		request.Header.Set("X-Forwarded-Proto", "https")
		response, err := transport.RoundTrip(request)
		if err != nil {
			http.Error(w, err.Error(), 503)
			return
		}
		defer response.Body.Close()
		for k, values := range response.Header {
			for _, value := range values {
				w.Header().Add(k, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		io.Copy(w, response.Body)
	})
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		request, _ := http.NewRequest("GET", origin+"/login", nil)
		request.URL.Scheme = "http"
		request.Header.Set("X-Forwarded-Proto", "https")
		response, err := transport.RoundTrip(request)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == 200 {
				return forwarding, stop
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	output, _ := os.ReadFile(log.Name())
	t.Fatalf("recovery child did not start: %s", output)
	return nil, stop
}
