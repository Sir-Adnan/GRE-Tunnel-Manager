package httpapi

import (
	"encoding/json"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"net/url"
	"testing"
)

func TestConfigurationRoutesRequireSessionCSRFAndClosedRequest(t *testing.T) {
	s := testServer(t)
	if w := request(s, "/api/configuration?id=F000001", "", "", "", nil); w.Code != 401 {
		t.Fatal("anonymous config read")
	}
	w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, "http://panel.local", "", nil)
	cookie := w.Result().Cookies()[0]
	var login struct {
		Session auth.Session `json:"session"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	w = request(s, "/api/inventory", "", "", "", cookie)
	var inv control.Inventory
	json.Unmarshal(w.Body.Bytes(), &inv)
	c := inv.Connections[0]
	w = request(s, "/api/configuration?id="+c.ID+"&revision="+url.QueryEscape(c.Revision), "", "", "", cookie)
	var v control.ConfigView
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Editor == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	in := control.ConfigInput{ID: c.ID, Revision: c.Revision, Format: "json", Text: v.Editor}
	b, _ := json.Marshal(in)
	if w = request(s, "/api/configuration/review", string(b), "http://panel.local", "", cookie); w.Code != 403 {
		t.Fatal("CSRF missing")
	}
	if w = request(s, "/api/configuration/review", string(b), "http://evil.local", login.Session.CSRF, cookie); w.Code != 403 {
		t.Fatal("foreign origin")
	}
	if w = request(s, "/api/configuration/review", string(b), "http://panel.local", login.Session.CSRF, cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(s, "/api/configuration/review", `{"file":"/etc/shadow"}`, "http://panel.local", login.Session.CSRF, cookie); w.Code != 400 {
		t.Fatal("file read field accepted")
	}
}

func TestImportAndEngineMaintenanceKeepAuthenticationAndOriginChecks(t *testing.T) {
	s := testServer(t)
	for _, path := range []string{"/api/engines/releases", "/api/configuration/import/review"} {
		if w := request(s, path, "", "", "", nil); w.Code != 401 {
			t.Fatal("anonymous access", path, w.Code)
		}
	}
	w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, "http://panel.local", "", nil)
	cookie := w.Result().Cookies()[0]
	var login struct {
		Session auth.Session `json:"session"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	if w = request(s, "/api/engines/releases", "", "", "", cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	body := `{"engine":"haproxy","format":"haproxy","text":"frontend test\n bind *:5000\n default_backend targets\nbackend targets\n server a 198.51.100.20:443 check\n"}`
	if w = request(s, "/api/configuration/import/review", body, "http://panel.local", "", cookie); w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if w = request(s, "/api/configuration/import/review", body, "http://evil.local", login.Session.CSRF, cookie); w.Code != 403 {
		t.Fatal("foreign origin accepted")
	}
	if w = request(s, "/api/configuration/import/review", body, "http://panel.local", login.Session.CSRF, cookie); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w = request(s, "/api/configuration/import/review", `{"file":"/etc/shadow"}`, "http://panel.local", login.Session.CSRF, cookie); w.Code != 400 {
		t.Fatal("arbitrary file field accepted")
	}
	if w = request(s, "/api/operations", `{"action":"engine-update","components":["haproxy"]}`, "http://panel.local", "", cookie); w.Code != 403 {
		t.Fatal("unauthenticated update accepted")
	}
}

func TestHostTelemetryRequiresSessionAndReturnsReadOnlyKernelSample(t *testing.T) {
	s := testServer(t)
	if w := request(s, "/api/host/telemetry", "", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, "http://panel.local", "", nil)
	cookie := w.Result().Cookies()[0]
	w = request(s, "/api/host/telemetry", "", "", "", cookie)
	var v control.HostTelemetry
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &v) != nil || v.Time.IsZero() || v.CPU == nil {
		t.Fatal(w.Code, w.Body.String())
	}
}
