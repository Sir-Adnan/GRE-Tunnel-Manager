package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/nodes"
)

type Server struct {
	Auth   *auth.Store
	Client control.Client
	Jobs   *Jobs
	Assets http.Handler
	Demo   bool
	Nodes  *nodes.Hub
	gate   chan struct{}
}

func New(ctx context.Context, a *auth.Store, c control.Client, assets http.Handler, demo bool) *Server {
	return &Server{Auth: a, Client: c, Jobs: NewJobs(ctx, c), Assets: assets, Demo: demo, gate: make(chan struct{}, 16)}
}
func reply(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}
func failure(w http.ResponseWriter, status int, message string) {
	reply(w, status, map[string]string{"error": message})
}
func decode(w http.ResponseWriter, r *http.Request, data any) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		failure(w, 415, "use application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 131072)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if d.Decode(data) != nil {
		failure(w, 400, "invalid request")
		return false
	}
	var next any
	if d.Decode(&next) != io.EOF {
		failure(w, 400, "one request required")
		return false
	}
	return true
}
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		if r.Method != "GET" && r.Method != "HEAD" {
			failure(w, 405, "method not allowed")
			return
		}
		s.Assets.ServeHTTP(w, r)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	default:
		failure(w, 503, "panel busy")
		return
	}
	if r.URL.Path == "/api/session" && r.Method == "GET" {
		session, ok := s.Auth.Get(r)
		reply(w, 200, map[string]any{"authenticated": ok, "session": session, "demo": s.Demo})
		return
	}
	if r.Method != "GET" && !auth.OriginOK(r) {
		failure(w, 403, "same-origin request required")
		return
	}
	if r.URL.Path == "/api/login" && r.Method == "POST" {
		var input struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !decode(w, r, &input) {
			return
		}
		if len(input.Username) > 40 || len(input.Password) > 72 {
			failure(w, 401, "invalid credentials")
			return
		}
		session, e := s.Auth.Login(w, r, input.Username, input.Password)
		if e != nil {
			failure(w, 401, e.Error())
			return
		}
		reply(w, 200, map[string]any{"authenticated": true, "session": session, "demo": s.Demo})
		return
	}
	session, ok := s.Auth.Get(r)
	if !ok {
		failure(w, 401, "sign in to continue")
		return
	}
	if r.Method != "GET" && !auth.CSRFOK(r, session) {
		failure(w, 403, "invalid CSRF token")
		return
	}
	switch {
	case r.URL.Path == "/api/configuration" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "configuration", Configuration: control.ConfigInput{ID: r.URL.Query().Get("id"), Revision: r.URL.Query().Get("revision")}})
	case r.URL.Path == "/api/configuration/review" && r.Method == "POST":
		var input control.ConfigInput
		if !decode(w, r, &input) {
			return
		}
		s.forward(w, r, control.Request{Action: "configuration-review", Configuration: input})
	case r.URL.Path == "/api/nodes" || strings.HasPrefix(r.URL.Path, "/api/nodes/"):
		s.nodeRoutes(w, r)
	case r.URL.Path == "/api/logout" && r.Method == "POST":
		s.Auth.Logout(w, r)
		reply(w, 200, map[string]bool{"ok": true})
	case r.URL.Path == "/api/inventory" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "inventory"})
	case r.URL.Path == "/api/metrics" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "metrics"})
	case r.URL.Path == "/api/metrics/history" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "metrics-history", Traffic: control.TrafficChange{ID: r.URL.Query().Get("id")}})
	case strings.HasPrefix(r.URL.Path, "/api/jobs/") && r.Method == "GET":
		job, ok := s.Jobs.Get(strings.TrimPrefix(r.URL.Path, "/api/jobs/"))
		if !ok {
			failure(w, 404, "job not found")
			return
		}
		reply(w, 200, job)
	case r.URL.Path == "/api/operations" && r.Method == "POST":
		var request control.Request
		if !decode(w, r, &request) {
			return
		}
		if !allowed(request.Action) {
			failure(w, 400, "unknown operation")
			return
		}
		job, e := s.Jobs.Start(request)
		if e != nil {
			failure(w, 409, e.Error())
			return
		}
		reply(w, 202, job)
	default:
		failure(w, 404, "not found")
	}
}
func allowed(action string) bool {
	switch action {
	case "create", "update", "enable", "disable", "delete", "plan", "doctor", "install", "gre-create", "gre-delete", "reverse-create", "reverse-delete", "service", "logs", "metrics-configure", "metrics-reset", "metrics-policy", "metrics-forget", "resource-rename", "configuration-apply":
		return true
	}
	return false
}
func (s *Server) forward(w http.ResponseWriter, r *http.Request, request control.Request) {
	data, e := s.Client.Do(r.Context(), request)
	if e != nil {
		failure(w, 502, e.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}
