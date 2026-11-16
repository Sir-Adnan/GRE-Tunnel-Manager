package httpapi

import (
	"encoding/json"
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
