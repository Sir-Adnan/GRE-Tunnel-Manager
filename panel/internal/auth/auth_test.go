package auth

import (
	"crypto/tls"
	"golang.org/x/crypto/bcrypt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSessionsCookieExpiryAndLogout(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("long-example-password"), 12)
	s := New("admin", string(hash), true)
	now := time.Now()
	s.Now = func() time.Time { return now }
	r := httptest.NewRequest("POST", "https://panel.example/api/login", nil)
	w := httptest.NewRecorder()
	session, e := s.Login(w, r, "admin", "long-example-password")
	if e != nil {
		t.Fatal(e)
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly || cookies[0].SameSite != 3 {
		t.Fatal(cookies)
	}
	r.AddCookie(cookies[0])
	if _, ok := s.Get(r); !ok {
		t.Fatal("missing session")
	}
	r.Header.Set("Origin", "https://panel.example")
	r.Header.Set("X-CSRF-Token", session.CSRF)
	r.TLS = &tls.ConnectionState{}
	if !CSRFOK(r, session) {
		t.Fatal("valid CSRF rejected")
	}
	r.Header.Set("Origin", "https://evil.example")
	if CSRFOK(r, session) {
		t.Fatal("cross-origin accepted")
	}
	s.Logout(w, r)
	if _, ok := s.Get(r); ok {
		t.Fatal("session remained")
	}
	r.Header.Set("Origin", "https://panel.example")
	w = httptest.NewRecorder()
	_, _ = s.Login(w, r, "admin", "long-example-password")
	r = httptest.NewRequest("GET", "https://panel.example/api/session", nil)
	r.AddCookie(w.Result().Cookies()[0])
	now = now.Add(5 * time.Hour)
	if _, ok := s.Get(r); ok {
		t.Fatal("expired session accepted")
	}
}

func TestHTTPLoginDoesNotReuseTheHTTPSCookieName(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("12345678"), 12)
	for _, secure := range []bool{true, false} {
		s := New("admin", string(hash), secure)
		r := httptest.NewRequest("POST", "http://panel.example/api/login", nil)
		w := httptest.NewRecorder()
		if _, e := s.Login(w, r, "admin", "12345678"); e != nil {
			t.Fatal(e)
		}
		cookie := w.Result().Cookies()[0]
		r.AddCookie(cookie)
		if _, ok := s.Get(r); !ok {
			t.Fatal("expected transport cookie rejected")
		}
		if secure {
			cookie.Name = HTTPCookieName
		} else {
			cookie.Name = CookieName
		}
		r = httptest.NewRequest("GET", "http://panel.example/api/session", nil)
		r.AddCookie(cookie)
		if _, ok := s.Get(r); ok {
			t.Fatal("opposite transport cookie accepted")
		}
		// An unrelated stale HTTPS cookie must not be changed by HTTP logout.
		if !secure {
			r.AddCookie(&http.Cookie{Name: CookieName, Value: "stale-secure-cookie"})
			w = httptest.NewRecorder()
			s.Logout(w, r)
			if w.Result().Cookies()[0].Name != HTTPCookieName {
				t.Fatal("HTTP logout touched HTTPS cookie")
			}
		}
	}
}
func TestBruteForceBounded(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("long-example-password"), 12)
	s := New("admin", string(hash), true)
	r := httptest.NewRequest("POST", "https://panel.example/api/login", nil)
	for i := 0; i < 5; i++ {
		if _, e := s.Login(httptest.NewRecorder(), r, "admin", "wrong"); e == nil {
			t.Fatal("wrong password")
		}
	}
	if _, e := s.Login(httptest.NewRecorder(), r, "admin", "long-example-password"); e == nil {
		t.Fatal("rate limit bypass")
	}
}
func TestIPv6RotationSharesOneLimitAndFullTableDoesNotLockOut(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("long-example-password"), bcrypt.MinCost)
	s := New("admin", string(hash), true)
	for i := 0; i < 5; i++ {
		r := httptest.NewRequest("POST", "https://panel.example/api/login", nil)
		r.RemoteAddr = "[2001:db8:1:2::" + string(rune('a'+i)) + "]:5000"
		s.Login(httptest.NewRecorder(), r, "admin", "wrong")
	}
	r := httptest.NewRequest("POST", "https://panel.example/api/login", nil)
	r.RemoteAddr = "[2001:db8:1:2:ffff::1]:5000"
	if _, e := s.Login(httptest.NewRecorder(), r, "admin", "long-example-password"); e == nil {
		t.Fatal("rotating addresses inside one /64 bypassed the limit")
	}
	// Fill the table with other clients; the administrator must still sign in.
	for i := 0; i < maxTrackedClients+10; i++ {
		s.attempts[time.Duration(i).String()] = attempt{Count: 1, Until: time.Now().Add(time.Minute + time.Duration(i))}
	}
	admin := httptest.NewRequest("POST", "https://panel.example/api/login", nil)
	admin.RemoteAddr = "198.51.100.7:5000"
	if _, e := s.Login(httptest.NewRecorder(), admin, "admin", "long-example-password"); e != nil {
		t.Fatal("full attempt table locked out a new client:", e)
	}
}
func TestOriginRejectsNullPortsAndScheme(t *testing.T) {
	r := httptest.NewRequest("POST", "https://127.0.0.1:8433/api/login", nil)
	for _, origin := range []string{"null", "https://evil.example", "http://127.0.0.1:8433", "https://127.0.0.1", "https://127.0.0.1:8433/path"} {
		r.Header.Set("Origin", origin)
		if OriginOK(r) {
			t.Fatal(origin)
		}
	}
	r.Header.Set("Origin", "https://127.0.0.1:8433")
	if !OriginOK(r) {
		t.Fatal("valid IP origin rejected")
	}
}
