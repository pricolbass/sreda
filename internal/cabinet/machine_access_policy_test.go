package cabinet_test

import (
	"net/url"
	"strings"
	"testing"
)

func TestAdministratorCannotDisableAnotherOwnersMachineConnection(t *testing.T) {
	app, admin, _ := setup(t)
	app.SetGateway(testGateway{})
	admin.login()
	alice := createOrdinary(t, admin, "alice")
	if signIn(alice, "alice", password) != 303 {
		t.Fatal("owner login failed")
	}
	credential := enrolledMachine(t, alice)
	page := admin.request("GET", "/machines", nil)
	if page.Code != 200 || !strings.Contains(page.Body.String(), "alice") {
		t.Fatal("administrator cannot inspect foreign machine")
	}
	if strings.Contains(page.Body.String(), `/machines/1/disable`) {
		t.Error("administrator received foreign machine disable action")
	}
	if w := admin.request("POST", "/machines/1/disable", url.Values{"revision": {"1"}}); w.Code != 404 {
		t.Errorf("foreign machine disable accepted: %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, alice, credential, `{"ready":true}`); w.Code != 200 {
		t.Fatalf("foreign administrator changed owner's connection: %d %s", w.Code, w.Body.String())
	}
	ownerPage := alice.request("GET", "/machines", nil)
	if !strings.Contains(ownerPage.Body.String(), `/machines/1/disable`) {
		t.Fatal("owner lost machine disable action")
	}
	if w := alice.request("POST", "/machines/1/disable", url.Values{"revision": {"1"}}); w.Code != 303 {
		t.Fatalf("owner machine disable failed: %d %s", w.Code, w.Body.String())
	}
	if w := agentContact(t, alice, credential, `{"ready":true}`); w.Code != 401 {
		t.Fatal("owner's explicit disable did not close connection")
	}
}
