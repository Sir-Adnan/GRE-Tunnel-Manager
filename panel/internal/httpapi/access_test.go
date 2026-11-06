package httpapi

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
)

func TestCertificateStatusAndReloadStayAuthenticatedAndLocal(t *testing.T) {
	s := testServer(t)
	reloads := 0
	s.Access = func() certificates.Status {
		return certificates.Status{Protocol: "https", Host: "panel.example", Fingerprint: "public-fingerprint"}
	}
	s.ReloadCertificate = func() error { reloads++; return nil }
	if w := request(s, "/api/access", "", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, "http://panel.local", "", nil)
	cookie := w.Result().Cookies()[0]
	var login struct {
		Session auth.Session `json:"session"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &login); e != nil {
		t.Fatal(e)
	}
	w = request(s, "/api/access", "", "", "", cookie)
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || !strings.Contains(w.Body.String(), "public-fingerprint") {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(s, "/api/access/reload", `{}`, "http://panel.local", "", cookie); w.Code != 403 || reloads != 0 {
		t.Fatal(w.Code, reloads)
	}
	if w = request(s, "/api/access/reload", `{}`, "http://evil.local", login.Session.CSRF, cookie); w.Code != 403 {
		t.Fatal(w.Code)
	}
	if w = request(s, "/api/access/reload", `{}`, "http://panel.local", login.Session.CSRF, cookie); w.Code != 200 || reloads != 1 {
		t.Fatal(w.Code, reloads)
	}
	if w = request(s, "/api/access/reload", `{"path":"/etc/shadow"}`, "http://panel.local", login.Session.CSRF, cookie); w.Code != 400 || reloads != 1 {
		t.Fatal("caller-supplied path accepted", w.Code, reloads)
	}
	s.ReloadCertificate = func() error { return errors.New("PRIVATE KEY DATA SHOULD NEVER BE RETURNED") }
	w = request(s, "/api/access/reload", `{}`, "http://panel.local", login.Session.CSRF, cookie)
	if w.Code != 409 || strings.Contains(w.Body.String(), "PRIVATE KEY") {
		t.Fatal(w.Code, w.Body.String())
	}
}
