package auth

import (
	"context"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/twofactor"
	"golang.org/x/crypto/bcrypt"
)

const testSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestTwoFactorLogin(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("long-example-password"), 12)
	s := New("admin", string(hash), true)
	now := time.Unix(1111111109, 0)
	s.Now = func() time.Time { return now }
	s.SetTwoFactor(testSecret)
	recovered := ""
	s.Recover = func(_ context.Context, code string) error {
		if code != "abcde-fghjk" {
			return errors.New("unknown")
		}
		recovered = code
		return nil
	}
	login := func(password, code string) error {
		r := httptest.NewRequest("POST", "https://panel.example/api/login", nil)
		r.RemoteAddr = "198.51.100.7:40000"
		_, e := s.LoginWithCode(httptest.NewRecorder(), r, "admin", password, code)
		return e
	}
	if e := login("wrong-password-x", ""); e == nil || errors.Is(e, ErrCodeRequired) {
		t.Fatal("a wrong password must not reach the code step", e)
	}
	if e := login("long-example-password", ""); !errors.Is(e, ErrCodeRequired) {
		t.Fatal(e)
	}
	if e := login("long-example-password", "123456"); e == nil {
		t.Fatal("wrong code accepted")
	}
	code, _ := twofactor.Code(testSecret, twofactor.Step(now))
	if e := login("long-example-password", code); e != nil {
		t.Fatal(e)
	}
	if e := login("long-example-password", code); e == nil {
		t.Fatal("a code was accepted twice")
	}
	if e := login("long-example-password", "abcde-fghjk"); e != nil || recovered != "abcde-fghjk" {
		t.Fatal(e, recovered)
	}
	s.SetTwoFactor("")
	if e := login("long-example-password", ""); e != nil {
		t.Fatal("password alone refused after two-factor sign-in was turned off", e)
	}
}

func TestSessionListAndRevoke(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("long-example-password"), 12)
	s := New("admin", string(hash), false)
	now := time.Now()
	s.Now = func() time.Time { return now }
	sign := func(agent string) *httptest.ResponseRecorder {
		r := httptest.NewRequest("POST", "http://panel.example/api/login", nil)
		r.Header.Set("User-Agent", agent+"\x00\n")
		r.RemoteAddr = "[::ffff:198.51.100.7]:40000"
		w := httptest.NewRecorder()
		if _, e := s.Login(w, r, "admin", "long-example-password"); e != nil {
			t.Fatal(e)
		}
		return w
	}
	first, second, third := sign("Firefox"), sign("Chrome"), sign("Safari")
	me := httptest.NewRequest("GET", "http://panel.example/api/security", nil)
	me.AddCookie(first.Result().Cookies()[0])
	list := s.Sessions(me)
	if len(list) != 3 || !list[0].Current || list[0].Agent != "Firefox" || list[0].Address != "198.51.100.7" || list[0].ID == "" {
		t.Fatal(list)
	}
	other := httptest.NewRequest("GET", "http://panel.example/", nil)
	other.AddCookie(second.Result().Cookies()[0])
	victim, _ := s.Get(other)
	if s.Revoke(me, victim.ID) != 1 {
		t.Fatal("session not revoked")
	}
	if _, ok := s.Get(other); ok {
		t.Fatal("revoked session still works")
	}
	if s.Revoke(me, list[0].ID) != 0 {
		t.Fatal("the current session must sign out with Logout")
	}
	if s.Revoke(me, "") != 1 {
		t.Fatal("other sessions not revoked")
	}
	last := httptest.NewRequest("GET", "http://panel.example/", nil)
	last.AddCookie(third.Result().Cookies()[0])
	if _, ok := s.Get(last); ok {
		t.Fatal("other session still works")
	}
	if _, ok := s.Get(me); !ok {
		t.Fatal("current session was signed out")
	}
}
