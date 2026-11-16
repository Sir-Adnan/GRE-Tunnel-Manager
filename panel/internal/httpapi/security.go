package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/twofactor"
)

// security holds two-factor setup in progress. A secret is created by the
// panel, shown once as a QR code and saved by the broker only after the
// operator proves the authenticator app produces matching codes.
type security struct {
	mu        sync.Mutex
	pending   map[string]pendingSecret // by session ID
	remaining int                      // unused recovery codes
}

type pendingSecret struct {
	secret  string
	expires time.Time
}

// SetTwoFactor applies the saved settings at startup.
func (s *Server) SetTwoFactor(settings twofactor.Settings, on bool) {
	if !on {
		s.Auth.SetTwoFactor("")
		return
	}
	s.Auth.SetTwoFactor(settings.Secret)
	s.security.mu.Lock()
	s.security.remaining = len(settings.Recovery)
	s.security.mu.Unlock()
}

// recoverCode consumes one recovery code through the broker.
func (s *Server) recoverCode(ctx context.Context, code string) error {
	data, e := s.Client.Do(ctx, control.Request{Action: "two-factor-recover", TwoFactor: control.TwoFactorInput{Code: code}})
	if e != nil {
		return e
	}
	var result control.TwoFactorResult
	if json.Unmarshal(data, &result) == nil {
		s.security.mu.Lock()
		s.security.remaining = result.Remaining
		s.security.mu.Unlock()
	}
	return nil
}

type securityView struct {
	TwoFactor bool               `json:"two_factor"`
	Remaining int                `json:"recovery_remaining"`
	Sessions  []auth.SessionInfo `json:"sessions"`
}

func (s *Server) securityView(r *http.Request) securityView {
	s.security.mu.Lock()
	remaining := s.security.remaining
	s.security.mu.Unlock()
	on := s.Auth.TwoFactor()
	if !on {
		remaining = 0
	}
	return securityView{TwoFactor: on, Remaining: remaining, Sessions: s.Auth.Sessions(r)}
}

// securityRoutes serves /api/security/*; the session and CSRF token are
// already checked.
func (s *Server) securityRoutes(w http.ResponseWriter, r *http.Request, session auth.Session) {
	switch {
	case r.URL.Path == "/api/security" && r.Method == "GET":
		reply(w, 200, s.securityView(r))
	case r.URL.Path == "/api/security/sessions/revoke" && r.Method == "POST":
		var input struct {
			ID     string `json:"id"`
			Others bool   `json:"others"`
		}
		if !decodeLimit(w, r, &input, 1024) {
			return
		}
		if (input.ID == "") == !input.Others || len(input.ID) > 32 {
			failure(w, 400, "choose one session or all other sessions")
			return
		}
		if input.Others {
			input.ID = ""
		}
		if s.Auth.Revoke(r, input.ID) == 0 && !input.Others {
			failure(w, 404, "that session has already ended")
			return
		}
		reply(w, 200, s.securityView(r))
	case r.URL.Path == "/api/security/two-factor/setup" && r.Method == "POST":
		var input struct{}
		if !decodeLimit(w, r, &input, 1024) {
			return
		}
		if s.Auth.TwoFactor() {
			failure(w, 409, "two-factor sign-in is already on")
			return
		}
		secret, e := twofactor.NewSecret()
		if e != nil {
			failure(w, 500, "could not create a secret")
			return
		}
		host, _, e := net.SplitHostPort(r.Host)
		if e != nil {
			host = r.Host
		}
		uri := twofactor.URI(secret, session.Username+"@"+host)
		qr, e := twofactor.QR(uri)
		if e != nil {
			failure(w, 500, "could not draw the QR code")
			return
		}
		s.security.mu.Lock()
		now := time.Now()
		for id, p := range s.security.pending {
			if now.After(p.expires) {
				delete(s.security.pending, id)
			}
		}
		s.security.pending[session.ID] = pendingSecret{secret: secret, expires: now.Add(15 * time.Minute)}
		s.security.mu.Unlock()
		reply(w, 200, map[string]any{"secret": secret, "uri": uri, "qr": qr})
	case r.URL.Path == "/api/security/two-factor/enable" && r.Method == "POST":
		var input struct {
			Code string `json:"code"`
		}
		if !decodeLimit(w, r, &input, 1024) {
			return
		}
		s.security.mu.Lock()
		p, ok := s.security.pending[session.ID]
		s.security.mu.Unlock()
		if !ok || time.Now().After(p.expires) {
			failure(w, 409, "the setup expired; start again")
			return
		}
		data, e := s.Client.Do(r.Context(), control.Request{Action: "two-factor-enable", TwoFactor: control.TwoFactorInput{Secret: p.secret, Code: input.Code}})
		if e != nil {
			failure(w, 400, e.Error())
			return
		}
		var result control.TwoFactorResult
		if json.Unmarshal(data, &result) != nil || len(result.Recovery) == 0 {
			failure(w, 502, "invalid broker answer")
			return
		}
		s.Auth.SetTwoFactor(p.secret)
		s.security.mu.Lock()
		delete(s.security.pending, session.ID)
		s.security.remaining = len(result.Recovery)
		s.security.mu.Unlock()
		reply(w, 200, map[string]any{"recovery": result.Recovery, "security": s.securityView(r)})
	case r.URL.Path == "/api/security/two-factor/disable" && r.Method == "POST":
		var input struct {
			Password string `json:"password"`
			Code     string `json:"code"`
		}
		if !decodeLimit(w, r, &input, 1024) {
			return
		}
		if len(input.Password) > 72 || len(input.Code) > 32 {
			failure(w, 400, "incorrect password or code")
			return
		}
		if _, e := s.Client.Do(r.Context(), control.Request{Action: "two-factor-disable", TwoFactor: control.TwoFactorInput{Password: input.Password, Code: input.Code}}); e != nil {
			failure(w, 400, e.Error())
			return
		}
		s.Auth.SetTwoFactor("")
		reply(w, 200, s.securityView(r))
	default:
		failure(w, 404, "not found")
	}
}

// loginReply explains a refused sign-in; code_required asks for step two.
func loginFailure(w http.ResponseWriter, e error) {
	if errors.Is(e, auth.ErrCodeRequired) {
		reply(w, 401, map[string]any{"error": e.Error(), "code_required": true})
		return
	}
	failure(w, 401, e.Error())
}
