package cabinet_test

import (
	"crypto/sha256"
	"database/sql"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sreda/internal/cabinet"
	"strings"
	"sync"
	"testing"
	"time"
)

func invitation(t *testing.T, admin *browser, lifetime string) string {
	t.Helper()
	if w := admin.request("GET", "/admin/invitations", nil); w.Code != 200 {
		t.Fatalf("invitation form: %d %s", w.Code, w.Body.String())
	}
	w := admin.request("POST", "/admin/invitations", url.Values{"lifetime": {lifetime}})
	if w.Code != 201 {
		t.Fatalf("create invitation: %d %s", w.Code, w.Body.String())
	}
	link := regexp.MustCompile(`/invite/[A-Za-z0-9_-]{43}`).FindString(w.Body.String())
	if link == "" {
		t.Fatal("missing invitation link")
	}
	return link
}
func visitor(t *testing.T, b *browser) *browser {
	return &browser{t: t, handler: b.handler, cookies: map[string]*http.Cookie{}}
}
func accept(t *testing.T, b *browser, link, login string) int {
	t.Helper()
	w := b.request("GET", link, nil)
	if w.Code != 200 {
		return w.Code
	}
	return b.request("POST", link, url.Values{"login": {login}, "password": {password}}).Code
}
func TestAdministratorInvitesUserWhoHasOwnCabinetAndNoAdminAccess(t *testing.T) {
	_, admin, _ := setup(t)
	admin.login()
	link := invitation(t, admin, "24h")
	person := visitor(t, admin)
	if w := person.request("GET", link, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Действует до") {
		t.Fatalf("invitation expiry: %d %s", w.Code, w.Body.String())
	}
	if code := accept(t, person, link, "alice"); code != 303 {
		t.Fatalf("accept: %d", code)
	}
	person.request("GET", "/login", nil)
	if w := person.request("POST", "/login", url.Values{"login": {"alice"}, "password": {password}}); w.Code != 303 {
		t.Fatalf("user login: %d", w.Code)
	}
	if w := person.request("GET", "/", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "alice") || strings.Contains(w.Body.String(), "Администратор Среды") {
		t.Fatalf("user cabinet: %d %s", w.Code, w.Body.String())
	}
	if w := person.request("GET", "/admin/invitations", nil); w.Code != 403 {
		t.Fatalf("admin listing: %d", w.Code)
	}
	if w := person.request("POST", "/admin/invitations", url.Values{"lifetime": {"24h"}}); w.Code != 403 {
		t.Fatalf("admin creation: %d", w.Code)
	}
	if w := person.request("POST", "/admin/invitations/1/cancel", nil); w.Code != 403 {
		t.Fatalf("admin cancellation: %d", w.Code)
	}
	if w := person.request("POST", "/logout", nil); w.Code != 303 {
		t.Fatalf("user logout: %d", w.Code)
	}
	if w := person.request("GET", "/", nil); w.Code != 303 {
		t.Fatalf("logged out cabinet: %d", w.Code)
	}
}

func TestInvitationCollisionKeepsLinkUsableAndUsedLinkRejectsInvalidForms(t *testing.T) {
	_, admin, _ := setup(t)
	admin.login()
	link := invitation(t, admin, "1h")
	person := visitor(t, admin)
	if code := accept(t, person, link, "owner"); code != 409 {
		t.Fatalf("collision: %d", code)
	}
	if code := accept(t, person, link, "alice"); code != 303 {
		t.Fatalf("retry: %d", code)
	}
	if code := accept(t, visitor(t, admin), link, "bob"); code != 410 {
		t.Fatalf("used link: %d", code)
	}
	// A stale open form cannot make an invalid link appear usable again.
	if w := person.request("POST", link, url.Values{"login": {"x"}, "password": {"short"}}); w.Code != 410 {
		t.Fatalf("used link invalid form: %d", w.Code)
	}
	admin.cookies = make(map[string]*http.Cookie)
	admin.login()
}

func TestCancellationAndUnfinishedRegistration(t *testing.T) {
	_, admin, _ := setup(t)
	admin.login()
	link := invitation(t, admin, "168h")
	person := visitor(t, admin)
	for i := 0; i < 2; i++ {
		if w := person.request("GET", link, nil); w.Code != 200 {
			t.Fatalf("reopen unfinished form: %d", w.Code)
		}
	}
	if w := person.request("POST", link, url.Values{"login": {"alice"}, "password": {"short"}}); w.Code != 400 {
		t.Fatalf("invalid form: %d", w.Code)
	}
	admin.request("GET", "/admin/invitations", nil)
	if w := admin.request("POST", "/admin/invitations/1/cancel", nil); w.Code != 303 {
		t.Fatalf("cancel: %d", w.Code)
	}
	if w := person.request("POST", link, url.Values{"login": {"alice"}, "password": {password}}); w.Code != 410 {
		t.Fatalf("cancelled stale form: %d", w.Code)
	}
	if w := person.request("GET", link, nil); w.Code != 410 {
		t.Fatalf("cancelled link: %d", w.Code)
	}
	w := admin.request("GET", "/admin/invitations", nil)
	if !strings.Contains(w.Body.String(), "Отменено") {
		t.Fatal("cancellation missing from admin list")
	}
}

func TestConcurrentInvitationAcceptanceAcrossApplicationInstancesCreatesOnlyOneAccount(t *testing.T) {
	_, admin, dir := setup(t)
	admin.login()
	link := invitation(t, admin, "24h")
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	people := []*browser{visitor(t, admin), visitor(t, admin)}
	people[1].handler = second.Handler()
	for _, person := range people {
		if w := person.request("GET", link, nil); w.Code != 200 {
			t.Fatal(w.Code)
		}
	}
	start := make(chan struct{})
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for i, person := range people {
		wg.Add(1)
		go func(i int, b *browser) {
			defer wg.Done()
			<-start
			codes <- b.request("POST", link, url.Values{"login": {[]string{"alice", "bob"}[i]}, "password": {password}}).Code
		}(i, person)
	}
	close(start)
	wg.Wait()
	close(codes)
	counts := map[int]int{}
	for code := range codes {
		counts[code]++
	}
	if counts[303] != 1 || counts[410] != 1 {
		t.Fatalf("concurrent acceptance: %+v", counts)
	}
	successes := 0
	for _, login := range []string{"alice", "bob"} {
		person := visitor(t, admin)
		person.request("GET", "/login", nil)
		w := person.request("POST", "/login", url.Values{"login": {login}, "password": {password}})
		if w.Code == 303 {
			successes++
		} else if w.Code != 401 {
			t.Fatalf("login %s: %d", login, w.Code)
		}
	}
	if successes != 1 {
		t.Fatalf("created accounts: %d", successes)
	}
}

// Legacy data are fixture setup, while all migration assertions go through HTTP.
func TestLegacyDatabaseMigrationPreservesSessionsAndRejectsExpiredInvitation(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite", filepath.Join(dir, "sreda.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	session := sha256.Sum256([]byte("legacy-session"))
	_, err = db.Exec(`CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);
 CREATE TABLE users(id INTEGER PRIMARY KEY,login TEXT NOT NULL UNIQUE,password_hash BLOB NOT NULL,role TEXT NOT NULL CHECK(role='admin'));
 CREATE TABLE sessions(token_hash BLOB PRIMARY KEY,user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,expires_at INTEGER NOT NULL);
 CREATE INDEX sessions_expiry ON sessions(expires_at); PRAGMA user_version=1;`)
	if err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO settings VALUES('origin',?)`, []any{origin}},
		{`INSERT INTO users VALUES(1,'owner',?,'admin')`, []any{hash}},
		{`INSERT INTO sessions VALUES(?,1,?)`, []any{session[:], time.Now().Add(time.Hour).Unix()}},
	} {
		if _, err = db.Exec(fixture.query, fixture.args...); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	app, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer app.Close()
	b := &browser{t: t, handler: app.Handler(), cookies: map[string]*http.Cookie{"__Host-sreda-session": {Name: "__Host-sreda-session", Value: "legacy-session"}}}
	if w := b.request("GET", "/", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "owner") {
		t.Fatalf("legacy session after migration: %d", w.Code)
	}
	link := invitation(t, b, "1h")
	app.Close()
	// Set the fixture's issuance time in the past to test actual expiry without a clock seam.
	db, err = sql.Open("sqlite", filepath.Join(dir, "sreda.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err = db.Exec(`UPDATE invitations SET expires_at=?`, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	db.Close()
	reopened, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	b.handler = reopened.Handler()
	person := visitor(t, b)
	if w := person.request("GET", link, nil); w.Code != 410 {
		t.Fatalf("expired link: %d", w.Code)
	}
	if w := b.request("GET", "/admin/invitations", nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Срок истёк") {
		t.Fatalf("expired invitation list: %d %s", w.Code, w.Body.String())
	}
	// Ordinary accounts can be created after rebuilding the old admin-only users table.
	if code := accept(t, person, invitation(t, b, "24h"), "alice"); code != 303 {
		t.Fatalf("ordinary account after migration: %d", code)
	}
}
