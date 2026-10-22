package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const CookieName = "gtm_session"

type Session struct {
	CSRF     string    `json:"csrf"`
	Expires  time.Time `json:"expires"`
	Username string    `json:"username"`
}
type attempt struct {
	Count int
	Until time.Time
}
type Store struct {
	mu         sync.Mutex
	sessions   map[[32]byte]Session
	attempts   map[string]attempt
	user, hash string
	Secure     bool
	Now        func() time.Time
}

func New(user, hash string, secure bool) *Store {
	return &Store{sessions: map[[32]byte]Session{}, attempts: map[string]attempt{}, user: user, hash: hash, Secure: secure, Now: time.Now}
}
func Random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}
func address(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		return r.RemoteAddr
	}
	return host
}
func (s *Store) Login(w http.ResponseWriter, r *http.Request, user, password string) (Session, error) {
	now := s.Now()
	ip := address(r)
	s.mu.Lock()
	for k, a := range s.attempts {
		if now.After(a.Until) {
			delete(s.attempts, k)
		}
	}
	a := s.attempts[ip]
	if a.Count >= 5 && now.Before(a.Until) {
		s.mu.Unlock()
		return Session{}, errors.New("too many login attempts; try again in 5 minutes")
	}
	if len(s.attempts) >= 1024 && a.Count == 0 {
		s.mu.Unlock()
		return Session{}, errors.New("login temporarily busy")
	}
	a.Count++
	a.Until = now.Add(5 * time.Minute)
	s.attempts[ip] = a
	s.mu.Unlock()
	// Always check a password hash even if the username is wrong.
	validPassword := bcrypt.CompareHashAndPassword([]byte(s.hash), []byte(password)) == nil
	u1, u2 := sha256.Sum256([]byte(user)), sha256.Sum256([]byte(s.user))
	if !validPassword || subtle.ConstantTimeCompare(u1[:], u2[:]) != 1 {
		return Session{}, errors.New("incorrect username or password")
	}
	token := Random()
	session := Session{CSRF: Random(), Expires: now.Add(4 * time.Hour), Username: s.user}
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.attempts, ip)
	for key, value := range s.sessions {
		if now.After(value.Expires) {
			delete(s.sessions, key)
		}
	}
	if len(s.sessions) >= 64 {
		return Session{}, errors.New("too many active sessions")
	}
	s.sessions[sha256.Sum256([]byte(token))] = session
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: token, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 14400})
	return session, nil
}
func (s *Store) Get(r *http.Request) (Session, bool) {
	c, e := r.Cookie(CookieName)
	if e != nil || len(c.Value) > 64 {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(c.Value))
	v, ok := s.sessions[key]
	if ok && s.Now().After(v.Expires) {
		delete(s.sessions, key)
		ok = false
	}
	return v, ok
}
func (s *Store) Logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie(CookieName); e == nil {
		s.mu.Lock()
		delete(s.sessions, sha256.Sum256([]byte(c.Value)))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: CookieName, Value: "", Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
}
func OriginOK(r *http.Request) bool {
	u, e := url.Parse(r.Header.Get("Origin"))
	scheme := "http"
	if r.TLS != nil {
		scheme = "https"
	}
	return e == nil && u.Host == r.Host && u.Scheme == scheme && u.Path == "" && u.RawQuery == "" && u.User == nil
}
func CSRFOK(r *http.Request, s Session) bool {
	return OriginOK(r) && subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(s.CSRF)) == 1
}
