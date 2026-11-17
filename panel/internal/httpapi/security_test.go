package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/twofactor"
)

func TestTwoFactorSetupLoginAndSessions(t *testing.T) {
	s := testServer(t)
	const origin = "http://panel.local"
	login := func(body string) (int, map[string]any) {
		w := request(s, "/api/login", body, origin, "", nil)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, origin, "", nil)
	var signedIn struct {
		Session auth.Session `json:"session"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &signedIn) != nil {
		t.Fatal(w.Code)
	}
	cookie, session := w.Result().Cookies()[0], signedIn.Session

	w = request(s, "/api/security/two-factor/setup", `{}`, origin, session.CSRF, cookie)
	var setup struct {
		Secret string   `json:"secret"`
		URI    string   `json:"uri"`
		QR     []string `json:"qr"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &setup) != nil || !twofactor.ValidSecret(setup.Secret) || len(setup.QR) < 21 || !strings.Contains(setup.URI, "admin@panel.local") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(s, "/api/security/two-factor/enable", `{"code":"12"}`, origin, session.CSRF, cookie); w.Code != 400 {
		t.Fatal("bad code enabled two-factor sign-in", w.Code)
	}
	now, _ := twofactor.Code(setup.Secret, twofactor.Step(time.Now()))
	w = request(s, "/api/security/two-factor/enable", `{"code":"`+now+`"}`, origin, session.CSRF, cookie)
	var enabled struct {
		Recovery []string `json:"recovery"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &enabled) != nil || len(enabled.Recovery) != 10 {
		t.Fatal(w.Code, w.Body.String())
	}
	// The browser that turned it on stays signed in.
	if w = request(s, "/api/security", "", "", "", cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"two_factor":true`) || !strings.Contains(w.Body.String(), `"recovery_remaining":10`) {
		t.Fatal(w.Code, w.Body.String())
	}

	code, out := login(`{"username":"admin","password":"test-panel-password"}`)
	if code != 401 || out["code_required"] != true {
		t.Fatal(code, out)
	}
	code, out = login(`{"username":"admin","password":"test-panel-password","code":"` + enabled.Recovery[0] + `"}`)
	if code != 200 {
		t.Fatal("recovery code refused", code, out)
	}
	if w = request(s, "/api/security", "", "", "", cookie); !strings.Contains(w.Body.String(), `"recovery_remaining":9`) {
		t.Fatal(w.Body.String())
	}
	if code, _ = login(`{"username":"admin","password":"test-panel-password","code":"` + enabled.Recovery[0] + `"}`); code != 401 {
		t.Fatal("recovery code reused")
	}

	// Sign out every other browser, then turn two-factor sign-in off.
	w = request(s, "/api/security/sessions/revoke", `{"others":true}`, origin, session.CSRF, cookie)
	var view securityView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &view) != nil || len(view.Sessions) != 1 || !view.Sessions[0].Current {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(s, "/api/security/sessions/revoke", `{"id":"","others":false}`, origin, session.CSRF, cookie); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = request(s, "/api/security/two-factor/disable", `{"password":"demo-panel-12345","code":"`+enabled.Recovery[1]+`"}`, origin, session.CSRF, cookie); w.Code != 200 || !strings.Contains(w.Body.String(), `"two_factor":false`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if code, _ = login(`{"username":"admin","password":"test-panel-password"}`); code != 200 {
		t.Fatal("password alone refused after turning two-factor sign-in off")
	}
	// Two-factor actions are never jobs.
	if w = request(s, "/api/operations", `{"action":"two-factor-disable"}`, origin, session.CSRF, cookie); w.Code != 400 {
		t.Fatal(w.Code)
	}
}

func TestPasswordChangeKeepsCallerAndSignsOutOthers(t *testing.T) {
	s := testServer(t)
	s.Demo = false // apply the new password to this process, as a real panel does
	const origin = "http://panel.local"
	signIn := func(password string) (int, *http.Cookie, auth.Session) {
		w := request(s, "/api/login", `{"username":"admin","password":"`+password+`"}`, origin, "", nil)
		var out struct {
			Session auth.Session `json:"session"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		if w.Code != 200 {
			return w.Code, nil, out.Session
		}
		return w.Code, w.Result().Cookies()[0], out.Session
	}
	_, cookie, session := signIn("test-panel-password")
	_, other, _ := signIn("test-panel-password")
	change := func(body string) int {
		return request(s, "/api/security/password", body, origin, session.CSRF, cookie).Code
	}
	// The demo broker's current password is demo-panel-12345.
	if code := change(`{"current":"demo-panel-12345","next":"short"}`); code != 400 {
		t.Fatal("short password accepted", code)
	}
	w := request(s, "/api/security/password", `{"current":"demo-panel-12345","next":"a-brand-new-password"}`, origin, session.CSRF, cookie)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"signed_out":1`) {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(s, "/api/security", "", "", "", cookie); w.Code != 200 {
		t.Fatal("the browser that changed the password was signed out", w.Code)
	}
	if w = request(s, "/api/security", "", "", "", other); w.Code == 200 {
		t.Fatal("another session survived the change")
	}
	if code, _, _ := signIn("test-panel-password"); code != 401 {
		t.Fatal("old password still works", code)
	}
	if code, _, _ := signIn("a-brand-new-password"); code != 200 {
		t.Fatal("new password refused", code)
	}
	// Five wrong current passwords pause changes for this session.
	for i := 0; i < 5; i++ {
		change(`{"current":"wrong-password-x","next":"another-new-password"}`)
	}
	if code := change(`{"current":"demo-panel-12345","next":"another-new-password"}`); code != 429 {
		t.Fatal("guessing was not limited", code)
	}
	// Never a job through the operations endpoint.
	if w = request(s, "/api/operations", `{"action":"panel-password"}`, origin, session.CSRF, cookie); w.Code != 400 {
		t.Fatal(w.Code)
	}
}
