package httpapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/nodes"
)

type Server struct {
	Auth       *auth.Store
	Client     control.Client
	Jobs       *Jobs
	Assets     http.Handler
	Demo       bool
	Nodes      *nodes.Hub
	gate       chan struct{}
	backupGate chan struct{}
}

func New(ctx context.Context, a *auth.Store, c control.Client, assets http.Handler, demo bool) *Server {
	return &Server{Auth: a, Client: c, Jobs: NewJobs(ctx, c), Assets: assets, Demo: demo, gate: make(chan struct{}, 16), backupGate: make(chan struct{}, 1)}
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
	return decodeLimit(w, r, data, 131072)
}
func decodeLimit(w http.ResponseWriter, r *http.Request, data any, limit int64) bool {
	if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		failure(w, 415, "use application/json")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, limit)
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
	if r.URL.Path == "/metrics" {
		s.prometheus(w, r)
		return
	}
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
	case r.URL.Path == "/api/host/telemetry" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "host-telemetry"})
	case r.URL.Path == "/api/health" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "health"})
	case r.URL.Path == "/api/health/report" && r.Method == "GET":
		week, e1 := strconv.Atoi(r.URL.Query().Get("week"))
		start, e2 := strconv.Atoi(r.URL.Query().Get("week_start"))
		if e1 != nil || e2 != nil {
			failure(w, 400, "invalid report week")
			return
		}
		s.forward(w, r, control.Request{Action: "health-report", Health: control.HealthInput{Week: week, WeekStart: start}})
	case r.URL.Path == "/api/health/flows" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "health-flows", Health: control.HealthInput{Owner: r.URL.Query().Get("owner")}})
	case r.URL.Path == "/api/health/mtu" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "health-mtu", Health: control.HealthInput{Owner: r.URL.Query().Get("owner")}})
	case r.URL.Path == "/api/optimize" && r.Method == "GET":
		q := r.URL.Query()
		s.forward(w, r, control.Request{Action: "optimize", Optimize: control.OptimizeInput{Level: q.Get("level"), Goal: q.Get("goal")}})
	case r.URL.Path == "/api/optimize/plan" && r.Method == "GET":
		q := r.URL.Query()
		in := control.OptimizeInput{Groups: strings.Split(q.Get("groups"), ","), Level: q.Get("level"), Goal: q.Get("goal")}
		// Custom values arrive as repeated set=key=value.
		for _, pair := range q["set"] {
			key, value, ok := strings.Cut(pair, "=")
			if !ok {
				failure(w, 400, "custom values are key=value")
				return
			}
			if in.Set == nil {
				in.Set = map[string]string{}
			}
			in.Set[key] = value
		}
		s.forward(w, r, control.Request{Action: "optimize-plan", Optimize: in})
	case r.URL.Path == "/api/prometheus" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "prometheus-settings"})
	case r.URL.Path == "/api/snapshots" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "snapshots"})
	case r.URL.Path == "/api/history" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "history"})
	case r.URL.Path == "/api/history/review" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "history-review", History: control.HistoryInput{Point: r.URL.Query().Get("point")}})
	case r.URL.Path == "/api/health/quality" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "gre-quality", Health: control.HealthInput{Owner: r.URL.Query().Get("owner")}})
	case r.URL.Path == "/api/diagnose" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "diagnose", Health: control.HealthInput{Owner: r.URL.Query().Get("owner")}})
	case r.URL.Path == "/api/notifications" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "notifications"})
	case r.URL.Path == "/api/notifications/read" && r.Method == "POST":
		var input control.NotifyInput
		if !decode(w, r, &input) {
			return
		}
		s.forward(w, r, control.Request{Action: "notifications-read", Notify: control.NotifyInput{IDs: input.IDs, All: input.All}})
	case r.URL.Path == "/api/notifications/clear" && r.Method == "POST":
		s.forward(w, r, control.Request{Action: "notifications-clear"})
	case r.URL.Path == "/api/maintenance" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "maintenance"})
	case r.URL.Path == "/api/engines/releases" && r.Method == "GET":
		s.forward(w, r, control.Request{Action: "engine-releases"})
	case r.URL.Path == "/api/configuration/import/review" && r.Method == "POST":
		var input control.ImportInput
		if !decode(w, r, &input) {
			return
		}
		s.forward(w, r, control.Request{Action: "configuration-import-review", Import: input})
	case strings.HasPrefix(r.URL.Path, "/api/backups/"):
		s.backupRoutes(w, r)
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
		if !control.PublicOperation(request.Action) {
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
func (s *Server) forward(w http.ResponseWriter, r *http.Request, request control.Request) {
	data, e := s.Client.Do(r.Context(), request)
	if e != nil {
		failure(w, 502, e.Error())
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

// prometheus serves /metrics to a scraper with a bearer token. It needs no
// session; the broker checks the token against its stored hash and renders
// only aggregate health, traffic and host gauges.
func (s *Server) prometheus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "GET" {
		failure(w, 405, "method not allowed")
		return
	}
	token, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok || token == "" {
		w.Header().Set("WWW-Authenticate", `Bearer realm="metrics"`)
		failure(w, 401, "bearer token required")
		return
	}
	select {
	case s.gate <- struct{}{}:
		defer func() { <-s.gate }()
	default:
		failure(w, 503, "panel busy")
		return
	}
	data, e := s.Client.Do(r.Context(), control.Request{Action: "prometheus", Prometheus: control.PrometheusInput{Token: token}})
	if e != nil {
		if e.Error() == "unauthorized" {
			failure(w, 401, "unauthorized")
			return
		}
		failure(w, 502, "metrics unavailable")
		return
	}
	var text string
	if json.Unmarshal(data, &text) != nil {
		failure(w, 502, "metrics unavailable")
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	io.WriteString(w, text)
}
