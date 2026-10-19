package cabinet_test

import (
	"bytes"
	"database/sql"
	"net/url"
	"path/filepath"
	"regexp"
	"sreda/internal/cabinet"
	"sreda/internal/command"
	"strings"
	"sync"
	"testing"
	"time"
)

const newPassword = "a brand new strong password"

func createOrdinary(t *testing.T, admin *browser, login string) *browser {
	t.Helper()
	person := visitor(t, admin)
	if code := accept(t, person, invitation(t, admin, "24h"), login); code != 303 {
		t.Fatalf("create %s: %d", login, code)
	}
	return person
}
func signIn(b *browser, login, password string) int {
	b.request("GET", "/login", nil)
	return b.request("POST", "/login", url.Values{"login": {login}, "password": {password}}).Code
}
func resetLink(t *testing.T, admin *browser, userID string) string {
	t.Helper()
	if w := admin.request("GET", "/admin/password-recovery", nil); w.Code != 200 {
		t.Fatalf("recovery administration: %d", w.Code)
	}
	w := admin.request("POST", "/admin/password-recovery", url.Values{"user_id": {userID}})
	if w.Code != 201 {
		t.Fatalf("recovery issuance: %d %s", w.Code, w.Body.String())
	}
	link := regexp.MustCompile(`/recover/[A-Za-z0-9_-]{43}`).FindString(w.Body.String())
	if link == "" {
		t.Fatal("missing recovery link")
	}
	return link
}
func TestUserRecoversPasswordAndAllExistingSessionsAreRevoked(t *testing.T) {
	_, admin, _ := setup(t)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	other := visitor(t, admin)
	if signIn(alice, "alice", password) != 303 || signIn(other, "alice", password) != 303 {
		t.Fatal("initial sign in")
	}
	link := resetLink(t, admin, "2")
	anonymous := visitor(t, admin)
	if w := anonymous.request("GET", link, nil); w.Code != 200 || !strings.Contains(w.Body.String(), "Действует до") {
		t.Fatalf("reset form: %d", w.Code)
	}
	// A submitted target cannot change the user bound to the one-time link.
	if w := anonymous.request("POST", link, url.Values{"password": {newPassword}, "user_id": {"1"}}); w.Code != 303 {
		t.Fatalf("password change: %d %s", w.Code, w.Body.String())
	}
	for _, session := range []*browser{alice, other} {
		if w := session.request("GET", "/", nil); w.Code != 303 {
			t.Fatalf("old session: %d", w.Code)
		}
	}
	if signIn(alice, "alice", password) != 401 || signIn(alice, "alice", newPassword) != 303 {
		t.Fatal("password replacement failed")
	}
	if w := alice.request("GET", "/admin/password-recovery", nil); w.Code != 403 {
		t.Fatalf("role changed: %d", w.Code)
	}
	if signIn(admin, "owner", password) != 303 {
		t.Fatal("administrator password changed")
	}
}

func TestOperatorResetsAdministratorPasswordLocallyAndRevokesSession(t *testing.T) {
	_, admin, dir := setup(t)
	admin.login()
	var output bytes.Buffer
	args := []string{"reset-admin", "--data-dir", dir, "--login", "owner", "--password-stdin"}
	if err := command.Run(args, strings.NewReader(newPassword+"\n"), &output, &output); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), newPassword) {
		t.Fatal("new password disclosed")
	}
	if w := admin.request("GET", "/", nil); w.Code != 303 {
		t.Fatalf("administrator old session: %d", w.Code)
	}
	if signIn(admin, "owner", password) != 401 || signIn(admin, "owner", newPassword) != 303 {
		t.Fatal("administrator password replacement")
	}
	if w := admin.request("GET", "/recover-admin", nil); w.Code != 404 {
		t.Fatal("public administrator recovery exists")
	}
}

func TestNextRecoveryLinkInvalidatesPreviousAndInvalidPasswordDoesNotConsumeLink(t *testing.T) {
	_, admin, _ := setup(t)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	old := resetLink(t, admin, "2")
	current := resetLink(t, admin, "2")
	if w := alice.request("GET", old, nil); w.Code != 410 {
		t.Fatalf("replaced link: %d", w.Code)
	}
	alice.request("GET", current, nil)
	for _, invalid := range []string{"short", strings.Repeat("x", 73)} {
		if w := alice.request("POST", current, url.Values{"password": {invalid}}); w.Code != 400 {
			t.Fatalf("invalid password: %d", w.Code)
		}
	}
	if w := alice.request("POST", current, url.Values{"password": {newPassword}}); w.Code != 303 {
		t.Fatalf("retry valid password: %d", w.Code)
	}
	if w := alice.request("POST", current, url.Values{"password": {password}}); w.Code != 410 {
		t.Fatalf("used link: %d", w.Code)
	}
	if signIn(alice, "alice", newPassword) != 303 {
		t.Fatal("final password")
	}
	if w := alice.request("POST", "/admin/password-recovery", url.Values{"user_id": {"1"}}); w.Code != 403 {
		t.Fatalf("ordinary user issued link: %d", w.Code)
	}
	admin.request("GET", "/admin/password-recovery", nil)
	if w := admin.request("POST", "/admin/password-recovery", url.Values{"user_id": {"1"}}); w.Code != 404 {
		t.Fatalf("public reset for administrator: %d", w.Code)
	}
}

func TestConcurrentRecoveryChangesPasswordOnceAcrossApplicationInstances(t *testing.T) {
	_, admin, dir := setup(t)
	admin.login()
	createOrdinary(t, admin, "alice")
	link := resetLink(t, admin, "2")
	second, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	people := []*browser{visitor(t, admin), visitor(t, admin)}
	people[1].handler = second.Handler()
	for _, person := range people {
		person.request("GET", link, nil)
	}
	start := make(chan struct{})
	codes := make(chan int, 2)
	var wg sync.WaitGroup
	for i, person := range people {
		wg.Add(1)
		go func(i int, b *browser) {
			defer wg.Done()
			<-start
			codes <- b.request("POST", link, url.Values{"password": {[]string{newPassword, password}[i]}}).Code
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
		t.Fatalf("concurrent changes: %+v", counts)
	}
	successes := 0
	for _, candidate := range []string{newPassword, password} {
		if signIn(visitor(t, admin), "alice", candidate) == 303 {
			successes++
		}
	}
	if successes != 1 {
		t.Fatalf("accepted passwords: %d", successes)
	}
}

func TestExpiredRecoveryAndOperatorCannotChangeOrdinaryAccount(t *testing.T) {
	app, admin, dir := setup(t)
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	link := resetLink(t, admin, "2")
	var output bytes.Buffer
	if err := command.Run([]string{"reset-admin", "--data-dir", dir, "--login", "alice", "--password-stdin"}, strings.NewReader(newPassword+"\n"), &output, &output); err == nil {
		t.Fatal("operator admin recovery changed ordinary user")
	}
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("ordinary password changed")
	}
	app.Close()
	db, err := sql.Open("sqlite", filepath.Join(dir, "sreda.sqlite3"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE password_recovery SET expires_at=?`, time.Now().Add(-time.Minute).Unix()); err != nil {
		t.Fatal(err)
	}
	db.Close()
	restarted, err := cabinet.Open(dir, "")
	if err != nil {
		t.Fatal(err)
	}
	defer restarted.Close()
	alice.handler = restarted.Handler()
	if w := alice.request("GET", link, nil); w.Code != 410 {
		t.Fatalf("expired form: %d", w.Code)
	}
	alice.request("GET", "/login", nil)
	if w := alice.request("POST", link, url.Values{"password": {newPassword}}); w.Code != 410 {
		t.Fatalf("expired post: %d", w.Code)
	}
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("expired recovery changed password")
	}
}
