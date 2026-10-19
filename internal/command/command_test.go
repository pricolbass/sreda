package command_test

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"sreda/internal/cabinet"
	"sreda/internal/command"
)

func TestManuallyCreatedAdministratorCanLogIn(t *testing.T) {
	dir := t.TempDir()
	var output bytes.Buffer
	err := command.Run([]string{"create-admin", "--data-dir", dir, "--origin", "https://sreda.example.test", "--login", "owner", "--password-stdin"}, strings.NewReader("correct horse battery staple\n"), &output, &output)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "correct horse battery staple") {
		t.Fatal("password leaked to output")
	}
	app, err := cabinet.Open(dir, "https://sreda.example.test")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	form := httptest.NewRecorder()
	app.Handler().ServeHTTP(form, httptest.NewRequest("GET", "https://sreda.example.test/login", nil))
	if form.Code != http.StatusOK {
		t.Fatalf("login page: got %d, want 200", form.Code)
	}
	token := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(form.Body.String())
	if len(token) != 2 {
		t.Fatal("login form has no CSRF token")
	}
	data := url.Values{"login": {"owner"}, "password": {"correct horse battery staple"}, "csrf": {token[1]}}
	req := httptest.NewRequest("POST", "https://sreda.example.test/login", strings.NewReader(data.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://sreda.example.test")
	for _, c := range form.Result().Cookies() {
		req.AddCookie(c)
	}
	response := httptest.NewRecorder()
	app.Handler().ServeHTTP(response, req)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
		t.Fatalf("login: got %d %s", response.Code, response.Body.String())
	}
	req = httptest.NewRequest("GET", "https://sreda.example.test/", nil)
	for _, c := range response.Result().Cookies() {
		req.AddCookie(c)
	}
	response = httptest.NewRecorder()
	app.Handler().ServeHTTP(response, req)
	body, _ := io.ReadAll(response.Result().Body)
	if response.Code != http.StatusOK || !strings.Contains(string(body), "owner") {
		t.Fatalf("cabinet: got %d %s", response.Code, body)
	}
}

func TestServeCommandRejectsTCPListener(t *testing.T) {
	var output bytes.Buffer
	err := command.Run([]string{"serve", "--data-dir", t.TempDir(), "--origin", "https://sreda.example.test", "--socket", "127.0.0.1:8080"}, strings.NewReader(""), &output, &output)
	if err == nil || !strings.Contains(err.Error(), "абсолютный путь") {
		t.Fatalf("expected Unix socket path validation, got %v", err)
	}
}
