package cabinet_test

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// caddyClient is optional because Caddy is an external deployment prerequisite.
// With SREDA_TEST_CADDY set, it validates a real wildcard TLS certificate from
// a local CA and traverses Caddy -> Unix socket -> the same gateway Handler.
func caddyClient(t *testing.T, handler http.Handler) (*http.Client, string) {
	t.Helper()
	binary := os.Getenv("SREDA_TEST_CADDY")
	if binary == "" {
		t.Skip("set SREDA_TEST_CADDY to exercise actual Caddy TLS/Unix boundary")
	}
	dir, err := os.MkdirTemp("/tmp", "sreda-caddy-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	socket := filepath.Join(dir, "http.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	backend := &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}
	go backend.Serve(listener)
	t.Cleanup(func() { backend.Close() })
	reserve, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	config := fmt.Sprintf("{\n auto_https disable_redirects\n admin off\n skip_install_trust\n}\nhttps://*.example.test:%d {\n bind 127.0.0.1\n tls internal\n reverse_proxy unix/%s {\n header_up X-Forwarded-Proto https\n }\n}\n", port, socket)
	path := filepath.Join(dir, "Caddyfile")
	if err = os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "caddy.log")
	log, err := os.Create(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	command := exec.Command(binary, "run", "--config", path, "--adapter", "caddyfile")
	command.Env = append(os.Environ(), "XDG_DATA_HOME="+filepath.Join(dir, "data"), "XDG_CONFIG_HOME="+filepath.Join(dir, "config"))
	command.Stdout = log
	command.Stderr = log
	if err = command.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { command.Process.Kill(); command.Wait() })
	var ca []byte
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		ca, err = os.ReadFile(filepath.Join(dir, "data", "caddy", "pki", "authorities", "local", "root.crt"))
		if err == nil {
			connection, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 50*time.Millisecond)
			if dialErr == nil {
				connection.Close()
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		output, _ := os.ReadFile(logPath)
		t.Fatalf("Caddy local CA unavailable: %v %s", err, output)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("invalid Caddy CA")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS12}, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, fmt.Sprintf("127.0.0.1:%d", port))
	}}
	t.Cleanup(transport.CloseIdleConnections)
	client:=&http.Client{Transport:transport,Timeout:10*time.Second}
 var probeErr error
 for time.Now().Before(deadline){response,err:=client.Get("https://application.example.test/");probeErr=err;if err==nil{response.Body.Close();break};time.Sleep(30*time.Millisecond)}
 if probeErr!=nil{output,_:=os.ReadFile(logPath);t.Fatalf("Caddy TLS probe: %v %s",probeErr,output)}

 return client,"https://application.example.test"
}
