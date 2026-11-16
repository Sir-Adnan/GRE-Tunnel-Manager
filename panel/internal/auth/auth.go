package auth

import (
	"context"
	"encoding/hex"
	"sort"
	"strings"

	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/twofactor"
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
	// ID is a short public name of the session (not its token).
	ID       string    `json:"id"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
	Address  string    `json:"address"`
	Agent    string    `json:"agent"`
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
	// secret is the TOTP secret while two-factor sign-in is on.
	secret   string
	lastStep int64
	// Recover consumes a single-use recovery code (through the broker,
	// which owns the file). Nil refuses recovery codes.
	Recover func(context.Context, string) error
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
	return s.LoginWithCode(w, r, user, password, "")
}

// LoginWithCode signs in with a password and, when two-factor sign-in is on,
// an authenticator or recovery code. A missing code returns ErrCodeRequired
// only after the password was accepted.
func (s *Store) LoginWithCode(w http.ResponseWriter, r *http.Request, user, password, code string) (Session, error) {
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
	if e := s.secondFactor(r, code, now); e != nil {
		return Session{}, e
	}
	token := Random()
	key := sha256.Sum256([]byte(token))
	session := Session{CSRF: Random(), Expires: now.Add(4 * time.Hour), Username: s.user,
		ID: hex.EncodeToString(key[:6]), Created: now, LastSeen: now, Address: clientAddress(r), Agent: agent(r)}
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
	s.sessions[key] = session
	http.SetCookie(w, &http.Cookie{Name: s.cookieName(), Value: token, Path: "/", HttpOnly: true, Secure: s.Secure, SameSite: http.SameSiteStrictMode, MaxAge: 14400})
	return session, nil
}
func (s *Store) key(r *http.Request) ([32]byte, bool) {
	c, e := r.Cookie(s.cookieName())
	if e != nil || len(c.Value) > 64 {
		return [32]byte{}, false
	}
	return sha256.Sum256([]byte(c.Value)), true
}

func (s *Store) Get(r *http.Request) (Session, bool) {
	key, ok := s.key(r)
	if !ok {
		return Session{}, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	v, ok := s.sessions[key]
	if ok && now.After(v.Expires) {
		delete(s.sessions, key)
		// An expired session must not echo its old CSRF token via /api/session.
		return Session{}, false
	}
	if ok && now.Sub(v.LastSeen) > 30*time.Second {
		v.LastSeen = now
		s.sessions[key] = v
	}
	return v, ok
}

// ErrCodeRequired asks for the second step of a two-factor sign-in.
var ErrCodeRequired = errors.New("enter the code from your authenticator app")

func (s *Store) secondFactor(r *http.Request, code string, now time.Time) error {
	s.mu.Lock()
	secret := s.secret
	s.mu.Unlock()
	if secret == "" {
		return nil
	}
	code = strings.TrimSpace(code)
	if code == "" {
		return ErrCodeRequired
	}
	wrong := errors.New("incorrect code")
	if twofactor.LooksLikeCode(code) {
		s.mu.Lock()
		defer s.mu.Unlock()
		step, ok := twofactor.Verify(secret, code, now, s.lastStep)
		if !ok || s.secret != secret {
			return wrong
		}
		s.lastStep = step
		return nil
	}
	if s.Recover == nil || len(code) > 32 || s.Recover(r.Context(), code) != nil {
		return wrong
	}
	return nil
}

// SetTwoFactor turns two-factor sign-in on (a TOTP secret) or off ("").
func (s *Store) SetTwoFactor(secret string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.secret != secret {
		s.secret, s.lastStep = secret, 0
	}
}

// TwoFactor reports whether sign-in asks for a second factor.
func (s *Store) TwoFactor() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.secret != ""
}

// SessionInfo describes one signed-in browser without its secrets.
type SessionInfo struct {
	ID       string    `json:"id"`
	Created  time.Time `json:"created"`
	LastSeen time.Time `json:"last_seen"`
	Expires  time.Time `json:"expires"`
	Address  string    `json:"address"`
	Agent    string    `json:"agent"`
	Current  bool      `json:"current"`
}

// Sessions lists active sessions, most recently used first.
func (s *Store) Sessions(r *http.Request) []SessionInfo {
	current, _ := s.key(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.Now()
	list := []SessionInfo{}
	for key, v := range s.sessions {
		if now.After(v.Expires) {
			delete(s.sessions, key)
			continue
		}
		list = append(list, SessionInfo{ID: v.ID, Created: v.Created, LastSeen: v.LastSeen, Expires: v.Expires, Address: v.Address, Agent: v.Agent, Current: key == current})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].Current != list[j].Current {
			return list[i].Current
		}
		return list[i].LastSeen.After(list[j].LastSeen)
	})
	return list
}

// Revoke signs out one other session by ID, or every other session when id
// is empty. The calling session is kept; it signs out with Logout.
func (s *Store) Revoke(r *http.Request, id string) int {
	current, _ := s.key(r)
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	for key, v := range s.sessions {
		if key != current && (id == "" || v.ID == id) {
			delete(s.sessions, key)
			removed++
		}
	}
	return removed
}

// clientAddress is the peer address shown in the session list.
func clientAddress(r *http.Request) string {
	host, _, e := net.SplitHostPort(r.RemoteAddr)
	if e != nil {
		host = r.RemoteAddr
	}
	if a, e := netip.ParseAddr(host); e == nil {
		return a.Unmap().WithZone("").String()
	}
	return ""
}

// agent keeps a short, printable User-Agent for the session list.
func agent(r *http.Request) string {
	var b strings.Builder
	for _, c := range r.UserAgent() {
		if b.Len() >= 200 {
			break
		}
		if c >= 0x20 && c < 0x7f {
			b.WriteRune(c)
		}
	}
	return b.String()
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
