package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
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

// Exercise real HTTP and TLS sockets: Secure cookies, CSRF and Origin must agree
// with the selected browser transport, not a forwarded-protocol header.
func TestBrowserAccessOverHTTPAndHTTPS(t *testing.T) {
	for _, secure := range []bool{false, true} {
		t.Run(map[bool]string{false: "HTTP", true: "HTTPS"}[secure], func(t *testing.T) {
			hash, _ := bcrypt.GenerateFromPassword([]byte("12345678"), 12)
			s := New(context.Background(), auth.New("admin", string(hash), secure), control.NewDemo(), http.NotFoundHandler(), false)
			var server *httptest.Server
			if secure {
				server = httptest.NewTLSServer(s)
			} else {
				server = httptest.NewServer(s)
			}
			defer server.Close()
			client := server.Client()
			client.Jar, _ = cookiejar.New(nil)
			call := func(path, body, origin, csrf string) (*http.Response, []byte) {
				t.Helper()
				method := "GET"
				if body != "" {
					method = "POST"
				}
				r, _ := http.NewRequest(method, server.URL+path, strings.NewReader(body))
				r.Header.Set("Content-Type", "application/json")
				r.Header.Set("Origin", origin)
				r.Header.Set("X-CSRF-Token", csrf)
				r.Header.Set("X-Forwarded-Proto", map[bool]string{true: "http", false: "https"}[secure])
				response, e := client.Do(r)
				if e != nil {
					t.Fatal(e)
				}
				data, _ := io.ReadAll(response.Body)
				response.Body.Close()
				return response, data
			}
			other := strings.Replace(server.URL, "http:", "https:", 1)
			if secure {
				other = strings.Replace(server.URL, "https:", "http:", 1)
			}
			if r, _ := call("/api/login", `{"username":"admin","password":"12345678"}`, other, ""); r.StatusCode != 403 {
				t.Fatal("opposite scheme accepted")
			}
			r, data := call("/api/login", `{"username":"admin","password":"12345678"}`, server.URL, "")
			if r.StatusCode != 200 {
				t.Fatal(r.StatusCode, string(data))
			}
			cookies := r.Cookies()
			name := auth.HTTPCookieName
			if secure {
				name = auth.CookieName
			}
			if len(cookies) != 1 || cookies[0].Name != name || cookies[0].Secure != secure || !cookies[0].HttpOnly || cookies[0].SameSite != http.SameSiteStrictMode {
				t.Fatal(cookies)
			}
			var result struct {
				Session auth.Session `json:"session"`
			}
			if e := json.Unmarshal(data, &result); e != nil {
				t.Fatal(e)
			}
			if r, _ = call("/api/inventory", "", "", ""); r.StatusCode != 200 {
				t.Fatal("cookie not sent by browser client", r.StatusCode)
			}
			for _, origin := range []string{"", other, "http://evil.example"} {
				if r, _ = call("/api/logout", "{}", origin, result.Session.CSRF); r.StatusCode != 403 {
					t.Fatal("invalid Origin accepted", origin)
				}
			}
			if r, _ = call("/api/logout", "{}", server.URL, "wrong"); r.StatusCode != 403 {
				t.Fatal("bad CSRF accepted")
			}
			if r, _ = call("/api/logout", "{}", server.URL, result.Session.CSRF); r.StatusCode != 200 || r.Cookies()[0].Secure != secure || r.Cookies()[0].MaxAge != -1 {
				t.Fatal("logout failed", r.StatusCode)
			}
			if r, _ = call("/api/inventory", "", "", ""); r.StatusCode != 401 {
				t.Fatal("logout retained cookie")
			}
		})
	}
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
