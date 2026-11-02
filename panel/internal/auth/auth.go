package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const CookieName = "gtm_session"
const HTTPCookieName = "gtm_session_http"

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

// Separate names avoid an existing Secure cookie blocking a later HTTP login
// on the same host. Neither store accepts the other transport's cookie.
func (s *Store) cookieName() string {
	if s.Secure {
		return CookieName
	}
	return HTTPCookieName
}
func Random() string {
	b := make([]byte, 32)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return base64.RawURLEncoding.EncodeToString(b)
}

// maxTrackedClients bounds the failed-login table.
const maxTrackedClients = 1024

// clientKey groups failed logins by IPv4 address or IPv6 /64. One IPv6 host
// usually controls a whole /64, so per-address keys would be trivial to rotate.
func clientKey(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		host = r.RemoteAddr
	}
	a, e := netip.ParseAddr(host)
	if e != nil {
		return host
	}
	a = a.Unmap().WithZone("")
	if a.Is6() {
		if p, e := a.Prefix(64); e == nil {
			return p.String()
		}
	}
	return a.String()
}
func (s *Store) Login(w http.ResponseWriter, r *http.Request, user, password string) (Session, error) {
	now := s.Now()
	ip := clientKey(r)
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
	if len(s.attempts) >= maxTrackedClients && a.Count == 0 {
		// Never refuse every new client because many others failed: that would
		// let an attacker lock the administrator out. Forget the oldest entry.
		oldest := ""
		for k, v := range s.attempts {
			if oldest == "" || v.Until.Before(s.attempts[oldest].Until) {
				oldest = k
			}
		}
		delete(s.attempts, oldest)
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
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: token, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 14400})
	return session, nil
}
func (s *Store) Get(r *http.Request) (Session, bool) {
	c, e := r.Cookie(s.cookieName())
	if e != nil || len(c.Value) > 64 {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := sha256.Sum256([]byte(c.Value))
	v, ok := s.sessions[key]
	if ok && s.Now().After(v.Expires) {
		delete(s.sessions, key)
		// An expired session must not echo its old CSRF token via /api/session.
		return Session{}, false
	}
	return v, ok
}
func (s *Store) Logout(w http.ResponseWriter, r *http.Request) {
	if c, e := r.Cookie(s.cookieName()); e == nil {
		s.mu.Lock()
		delete(s.sessions, sha256.Sum256([]byte(c.Value)))
		s.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: "", Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: -1})
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
