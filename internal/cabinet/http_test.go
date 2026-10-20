package cabinet_test

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"sreda/internal/cabinet"
)

const origin = "https://sreda.example.test"
const password = "correct horse battery staple"

// browser exercises forms and cookies through HTTP, without database inspection.
type browser struct {
	t       *testing.T
	handler http.Handler
	cookies map[string]*http.Cookie
	csrf    string
	origin  string
}

func (b *browser) request(method, path string, values url.Values) *httptest.ResponseRecorder {
	b.t.Helper()
	if values == nil {
		values = url.Values{}
	}
	if method == "POST" {
		values.Set("csrf", b.csrf)
	}
	base := b.origin
	if base == "" {
		base = origin
	}
	r := httptest.NewRequest(method, base+path, strings.NewReader(values.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("Origin", base)
	for _, c := range b.cookies {
		r.AddCookie(c)
	}
	w := httptest.NewRecorder()
	b.handler.ServeHTTP(w, r)
	for _, c := range w.Result().Cookies() {
		b.cookies[c.Name] = c
	}
	match := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindStringSubmatch(w.Body.String())
	if len(match) == 2 {
		b.csrf = match[1]
	}
	return w
}

func setup(t *testing.T) (*cabinet.App, *browser, string) {
	t.Helper()
	dir := t.TempDir()
	app, err := cabinet.Open(dir, origin)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { app.Close() })
	if err := app.CreateAdministrator("owner", password); err != nil {
		t.Fatal(err)
	}
	return app, &browser{t: t, handler: app.Handler(), cookies: make(map[string]*http.Cookie)}, dir
}

func (b *browser) login() {
	b.t.Helper()
	if w := b.request("GET", "/login", nil); w.Code != 200 {
		b.t.Fatalf("form: %d", w.Code)
	}
	if w := b.request("POST", "/login", url.Values{"login": {"owner"}, "password": {password}}); w.Code != 303 {
		b.t.Fatalf("login: %d %s", w.Code, w.Body.String())
	}
}

func TestLogoutRevokesSessionIncludingReplayAfterRestart(t *testing.T) {
	app, b, dir := setup(t)
	b.login()
	old := *b.cookies["__Host-sreda-session"]
	if w := b.request("GET", "/", nil); w.Code != 200 {
		t.Fatalf("cabinet: %d", w.Code)
	}
	if w := b.request("POST", "/logout", nil); w.Code != 303 {
		t.Fatalf("logout: %d", w.Code)
	}
	if b.cookies["__Host-sreda-session"].MaxAge != -1 {
		t.Fatal("logout did not expire cookie")
	}
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	b.handler = restarted.Handler()
	b.cookies[old.Name] = &old
	if w := b.request("GET", "/", nil); w.Code != 303 || w.Header().Get("Location") != "/login" {
		t.Fatalf("revoked session accepted: %d", w.Code)
	}
}

func TestAccountAndSessionSurviveReopen(t *testing.T) {
	app, b, dir := setup(t)
	b.login()
	if err := app.Close(); err != nil {
		t.Fatal(err)
	}
	restarted, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	b.handler = restarted.Handler()
	w := b.request("GET", "/", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "owner") {
		t.Fatalf("saved session: %d", w.Code)
	}
	b.cookies = make(map[string]*http.Cookie)
	b.login()
}

func TestUnauthorizedRequestsCannotReachCabinet(t *testing.T) {
	_, b, _ := setup(t)
	for _, token := range []string{"", "invented-session", strings.Repeat("a", 43)} {
		b.cookies["__Host-sreda-session"] = &http.Cookie{Name: "__Host-sreda-session", Value: token}
		if w := b.request("GET", "/", nil); w.Code != 303 || strings.Contains(w.Body.String(), "owner") {
			t.Fatalf("unauthorized response: %d %s", w.Code, w.Body.String())
		}
	}
	for _, path := range []string{"/register", "/setup", "/admin", "/create-admin"} {
		if w := b.request("GET", path, nil); w.Code != 404 {
			t.Fatalf("unexpected public route %s: %d", path, w.Code)
		}
	}
}

func TestWrongCredentialsAndDuplicateCreationDoNotReplaceAdministrator(t *testing.T) {
	app, b, _ := setup(t)
	if err := app.CreateAdministrator("owner", "a different valid password"); err == nil {
		t.Fatal("duplicate administrator accepted")
	}
	for _, credentials := range []url.Values{
		{"login": {"owner"}, "password": {"wrong password"}},
		{"login": {"unknown"}, "password": {password}},
		{"login": {"owner' OR 1=1 --"}, "password": {password}},
	} {
		b.request("GET", "/login", nil)
		w := b.request("POST", "/login", credentials)
		if w.Code != 401 || !strings.Contains(w.Body.String(), "Неверный логин или пароль") {
			t.Fatalf("invalid login: %d", w.Code)
		}
		if c := b.cookies["__Host-sreda-session"]; c != nil {
			t.Fatal("session created for invalid credentials")
		}
	}
	b.login()
}

func TestCSRFAndHTTPRequestsAreRejected(t *testing.T) {
	_, b, _ := setup(t)
	b.login()
	b.request("GET", "/", nil)
	for _, tc := range []struct {
		name, target, host, requestOrigin, csrf string
		cookie                                  bool
		status                                  int
	}{
		{"missing token", origin + "/logout", "sreda.example.test", origin, "", true, 403},
		{"missing cookie", origin + "/logout", "sreda.example.test", origin, b.csrf, false, 403},
		{"sibling origin", origin + "/logout", "sreda.example.test", "https://evil.example.test", b.csrf, true, 403},
		{"missing origin", origin + "/logout", "sreda.example.test", "", b.csrf, true, 403},
		{"plain HTTP", "http://sreda.example.test/logout", "sreda.example.test", origin, b.csrf, true, 403},
		{"wrong host", origin + "/logout", "evil.example.test", origin, b.csrf, true, 400},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.target, strings.NewReader(url.Values{"csrf": {tc.csrf}}.Encode()))
			r.Host = tc.host
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", tc.requestOrigin)
			if tc.cookie {
				for _, c := range b.cookies {
					r.AddCookie(c)
				}
			}
			w := httptest.NewRecorder()
			b.handler.ServeHTTP(w, r)
			if w.Code != tc.status || w.Header().Get("Location") != "" {
				t.Fatalf("got %d, want %d without redirect", w.Code, tc.status)
			}
		})
	}
	if w := b.request("GET", "/logout", nil); w.Code != 405 {
		t.Fatalf("GET logout: %d", w.Code)
	}
	if w := b.request("GET", "/", nil); w.Code != 200 {
		t.Fatal("rejected logout revoked session")
	}
}

func TestLoginRotatesSessionAndCookiesAreHostOnlySecure(t *testing.T) {
	_, b, _ := setup(t)
	b.login()
	old := *b.cookies["__Host-sreda-session"]
	b.login()
	for _, name := range []string{"__Host-sreda-session", "__Host-sreda-csrf"} {
		c := b.cookies[name]
		if c == nil || !c.Secure || !c.HttpOnly || c.SameSite != http.SameSiteStrictMode || c.Domain != "" || c.Path != "/" {
			t.Fatalf("unsafe cookie %s: %+v", name, c)
		}
	}
	if old.Value == b.cookies[old.Name].Value {
		t.Fatal("session was not rotated")
	}
	b.cookies[old.Name] = &old
	if w := b.request("GET", "/", nil); w.Code != 303 {
		t.Fatal("old session remains usable")
	}
}
