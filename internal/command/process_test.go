package command_test

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"

	"sreda/internal/command"
)

func TestCLIProcess(t *testing.T) {
	if os.Getenv("SREDA_TEST_CHILD") != "1" {
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

func child(t *testing.T, args ...string) *exec.Cmd {
	t.Helper()
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, append([]string{"-test.run=^TestCLIProcess$", "--"}, args...)...)
	cmd.Env = append(os.Environ(), "SREDA_TEST_CHILD=1")
	return cmd
}

func TestAccountAndSessionSurviveServerProcessRestart(t *testing.T) {
	// Short path also works with macOS's Unix socket path limit.
	dir, err := os.MkdirTemp("/tmp", "sreda-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	dataDir := filepath.Join(dir, "data")
	socket := filepath.Join(dir, "http.sock")
	create := child(t, "create-admin", "--data-dir", dataDir, "--origin", "https://sreda.example.test", "--login", "owner", "--password-stdin")
	create.Stdin = strings.NewReader("correct horse battery staple\n")
	if output, err := create.CombinedOutput(); err != nil {
		t.Fatalf("create-admin: %v %s", err, output)
	}
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", socket)
	}}
	defer transport.CloseIdleConnections()
	// bcrypt is deliberately expensive; the race detector adds substantial overhead.
	client := &http.Client{Transport: transport, Timeout: 15 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request := func(method, path, body string, cookies []*http.Cookie) (int, string, []*http.Cookie, error) {
		req, _ := http.NewRequest(method, "http://sreda.example.test"+path, strings.NewReader(body))
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("Origin", "https://sreda.example.test")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		for _, c := range cookies {
			req.AddCookie(c)
		}
		resp, err := client.Do(req)
		if err != nil {
			return 0, "", nil, err
		}
		defer resp.Body.Close()
		text, err := io.ReadAll(resp.Body)
		return resp.StatusCode, string(text), resp.Cookies(), err
	}
	start := func() func() {
		cmd := child(t, "serve", "--data-dir", dataDir, "--socket", socket)
		log, err := os.CreateTemp(dir, "server-log-")
		if err != nil {
			t.Fatal(err)
		}
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		stopped := false
		stop := func() {
			if stopped {
				return
			}
			stopped = true
			cmd.Process.Signal(syscall.SIGTERM)
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("serve exit: %v", err)
				}
			case <-time.After(15 * time.Second):
				cmd.Process.Kill()
				<-done
				t.Error("server did not stop")
			}
			log.Close()
			transport.CloseIdleConnections()
		}
		t.Cleanup(stop)
		deadline := time.Now().Add(10 * time.Second)
		for time.Now().Before(deadline) {
			if code, _, _, err := request("GET", "/login", "", nil); err == nil && code == 200 {
				return stop
			}
			time.Sleep(20 * time.Millisecond)
		}
		output, _ := os.ReadFile(log.Name())
		t.Fatalf("server did not start: %s", output)
		return stop
	}
	stop := start()
	_, page, cookies, err := request("GET", "/login", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(page)
	if len(match) != 2 {
		t.Fatal("missing CSRF field")
	}
	code, _, session, err := request("POST", "/login", url.Values{"csrf": {match[1]}, "login": {"owner"}, "password": {"correct horse battery staple"}}.Encode(), cookies)
	if err != nil || code != 303 {
		t.Fatalf("login: %d %v", code, err)
	}
	stop()
	start()
	code, page, _, err = request("GET", "/", "", session)
	if err != nil || code != 200 || !strings.Contains(page, "owner") {
		t.Fatalf("restart lost account/session: %d %v %s", code, err, page)
	}
}
