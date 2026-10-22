package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"golang.org/x/crypto/bcrypt"
)

func testServer(t *testing.T) *Server {
	t.Helper()
	hash, e := bcrypt.GenerateFromPassword([]byte("test-panel-password"), 12)
	if e != nil {
		t.Fatal(e)
	}
	return New(context.Background(), auth.New("admin", string(hash), false), control.NewDemo(), http.NotFoundHandler(), true)
}
func request(server *Server, path, body, origin, csrf string, cookie *http.Cookie) *httptest.ResponseRecorder {
	method := "GET"
	if body != "" {
		method = "POST"
	}
	r := httptest.NewRequest(method, "http://panel.local"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", origin)
	r.Header.Set("X-CSRF-Token", csrf)
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	return w
}
func TestAuthenticationCSRFAndUnknownOperations(t *testing.T) {
	s := testServer(t)
	if w := request(s, "/api/inventory", "", "", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	if w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, "http://evil.local", "", nil); w.Code != 403 {
		t.Fatal(w.Code)
	}
	w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, "http://panel.local", "", nil)
	if w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	var response struct {
		Session auth.Session `json:"session"`
	}
	json.Unmarshal(w.Body.Bytes(), &response)
	if response.Session.CSRF == "" {
		t.Fatal("missing CSRF")
	}
	if w = request(s, "/api/operations", `{"action":"install","components":["haproxy"]}`, "http://panel.local", "", cookie); w.Code != 403 {
		t.Fatal("missing CSRF accepted", w.Code)
	}
	if w = request(s, "/api/operations", `{"action":"exec","command":"id"}`, "http://panel.local", response.Session.CSRF, cookie); w.Code != 400 {
		t.Fatal("unknown command accepted", w.Code)
	}
	if w = request(s, "/api/operations", `{"action":"exec"}`, "http://panel.local", response.Session.CSRF, cookie); w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w = request(s, "/api/inventory", "", "", "", cookie); w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"demo":true`)) {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(s, "/api/logout", "{}", "http://panel.local", response.Session.CSRF, cookie)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if w = request(s, "/api/inventory", "", "", "", cookie); w.Code != 401 {
		t.Fatal("logout retained session")
	}
}
func TestLoginBodyBoundAndSecurityHeaders(t *testing.T) {
	s := testServer(t)
	w := request(s, "/api/login", strings.Repeat("x", 140000), "http://panel.local", "", nil)
	if w.Code != 400 {
		t.Fatal(w.Code)
	}
	if w.Header().Get("Content-Security-Policy") == "" || w.Header().Get("X-Frame-Options") != "DENY" {
		t.Fatal(w.Header())
	}
}
