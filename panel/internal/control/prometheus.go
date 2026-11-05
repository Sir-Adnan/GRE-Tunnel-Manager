package control

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/version"
)

// PrometheusInput turns the read-only /metrics endpoint on or off; Rotate
// issues a new bearer token (shown once).
type PrometheusInput struct {
	Enabled  bool   `json:"enabled"`
	Rotate   bool   `json:"rotate,omitempty"`
	Revision uint64 `json:"revision"`
	// Token is the presented bearer token of a scrape (prometheus action).
	Token string `json:"token,omitempty"`
}

type PrometheusView struct {
	Enabled  bool   `json:"enabled"`
	TokenSet bool   `json:"token_set"`
	Revision uint64 `json:"revision"`
	// Token is returned only by the change that created it.
	Token string `json:"token,omitempty"`
	Path  string `json:"path"`
}

type prometheusState struct {
	Enabled  bool   `json:"enabled"`
	Hash     string `json:"hash,omitempty"`
	Revision uint64 `json:"revision"`
}

// Prometheus stores only a SHA-256 hash of the token.
type Prometheus struct {
	mu    sync.Mutex
	path  string
	state prometheusState
}

func OpenPrometheus(path string) (*Prometheus, error) {
	p := &Prometheus{path: path}
	data, e := os.ReadFile(path)
	if errors.Is(e, os.ErrNotExist) {
		return p, nil
	}
	if e != nil {
		return nil, e
	}
	return p, json.Unmarshal(data, &p.state)
}

func (p *Prometheus) View() PrometheusView {
	p.mu.Lock()
	defer p.mu.Unlock()
	return PrometheusView{Enabled: p.state.Enabled, TokenSet: p.state.Hash != "", Revision: p.state.Revision, Path: "/metrics"}
}

func (p *Prometheus) Configure(in PrometheusInput) (PrometheusView, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if in.Revision != p.state.Revision {
		return PrometheusView{}, errors.New("metrics settings changed; reload and try again")
	}
	token := ""
	if in.Rotate || (in.Enabled && p.state.Hash == "") {
		b := make([]byte, 24)
		if _, e := rand.Read(b); e != nil {
			return PrometheusView{}, e
		}
		token = "gtm_" + hex.EncodeToString(b)
		sum := sha256.Sum256([]byte(token))
		p.state.Hash = hex.EncodeToString(sum[:])
	}
	p.state.Enabled = in.Enabled
	p.state.Revision++
	if p.path != "" {
		data, _ := json.Marshal(p.state)
		if e := os.MkdirAll(filepath.Dir(p.path), 0700); e != nil {
			return PrometheusView{}, e
		}
		if e := os.WriteFile(p.path+".tmp", data, 0600); e != nil {
			return PrometheusView{}, e
		}
		if e := os.Rename(p.path+".tmp", p.path); e != nil {
			return PrometheusView{}, e
		}
	}
	return PrometheusView{Enabled: p.state.Enabled, TokenSet: p.state.Hash != "", Revision: p.state.Revision, Token: token, Path: "/metrics"}, nil
}

// Allowed checks a scrape token in constant time.
func (p *Prometheus) Allowed(token string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.state.Enabled || p.state.Hash == "" || len(token) > 128 {
		return false
	}
	sum := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare([]byte(hex.EncodeToString(sum[:])), []byte(p.state.Hash)) == 1
}

// promWriter renders the text exposition format (version 0.0.4).
type promWriter struct {
	b    strings.Builder
	seen map[string]bool
}

func promEscape(v string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`).Replace(v)
}

func (w *promWriter) metric(name, kind, help string, labels map[string]string, value float64) {
	if w.seen == nil {
		w.seen = map[string]bool{}
	}
	if !w.seen[name] {
		w.seen[name] = true
		fmt.Fprintf(&w.b, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
	}
	w.b.WriteString(name)
	if len(labels) > 0 {
		keys := make([]string, 0, len(labels))
		for k := range labels {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, len(keys))
		for i, k := range keys {
			parts[i] = k + `="` + promEscape(labels[k]) + `"`
		}
		w.b.WriteString("{" + strings.Join(parts, ",") + "}")
	}
	fmt.Fprintf(&w.b, " %g\n", value)
}

var statusValue = map[string]float64{health.StatusUp: 1, health.StatusDegraded: 0.5, health.StatusDown: 0}

// prometheusText renders health, traffic and host gauges. Unknown health
// states are omitted rather than reported as down.
func prometheusText(host string, view *health.View, traffic *MetricsView, telemetry HostTelemetry, unread int) string {
	w := &promWriter{}
	w.metric("gtm_info", "gauge", "Traffic Manager build information.", map[string]string{"version": version.Number, "host": host}, 1)
	if view != nil {
		w.metric("gtm_health_enabled", "gauge", "1 while health monitoring is on.", nil, map[bool]float64{true: 1, false: 0}[view.Settings.Enabled])
		w.metric("gtm_health_open_outages", "gauge", "Outages that have not ended.", nil, float64(view.Summary.OpenOutages))
		for _, o := range view.Owners {
			labels := map[string]string{"id": o.Owner, "name": o.Name, "engine": o.Engine}
			if v, ok := statusValue[o.Status]; ok {
				w.metric("gtm_connection_up", "gauge", "Health status: 1 up, 0.5 degraded, 0 down.", labels, v)
			}
			if o.Latency != nil {
				w.metric("gtm_connection_latency_milliseconds", "gauge", "Average probe round-trip time.", labels, *o.Latency)
			}
			if o.Uptime24h != nil {
				w.metric("gtm_connection_uptime_ratio_24h", "gauge", "Share of healthy checks in the last 24 hours.", labels, *o.Uptime24h/100)
			}
		}
		if h := view.Host; h != nil {
			if h.ConntrackCount != nil {
				w.metric("gtm_conntrack_entries", "gauge", "Tracked flows.", nil, float64(*h.ConntrackCount))
			}
			if h.ConntrackMax != nil {
				w.metric("gtm_conntrack_limit", "gauge", "Flow table limit.", nil, float64(*h.ConntrackMax))
			}
			if h.SoftIRQ != nil {
				w.metric("gtm_host_softirq_percent", "gauge", "Share of CPU time in softirq.", nil, *h.SoftIRQ)
			}
			if h.Steal != nil {
				w.metric("gtm_host_steal_percent", "gauge", "Share of CPU time stolen by the hypervisor.", nil, *h.Steal)
			}
		}
	}
	if traffic != nil {
		ids := make([]string, 0, len(traffic.Counters))
		for id := range traffic.Counters {
			ids = append(ids, id)
		}
		sort.Strings(ids)
		for _, id := range ids {
			c := traffic.Counters[id]
			w.metric("gtm_traffic_received_bytes_total", "counter", "Bytes received in the current traffic cycle.", map[string]string{"id": id}, float64(c.Received))
			w.metric("gtm_traffic_sent_bytes_total", "counter", "Bytes sent in the current traffic cycle.", map[string]string{"id": id}, float64(c.Sent))
		}
	}
	if telemetry.CPU != nil {
		w.metric("gtm_host_cpu_percent", "gauge", "CPU use over the sampling window.", nil, *telemetry.CPU)
	}
	if telemetry.MemoryTotal > 0 {
		w.metric("gtm_host_memory_total_bytes", "gauge", "Total memory.", nil, float64(telemetry.MemoryTotal))
		w.metric("gtm_host_memory_available_bytes", "gauge", "Available memory.", nil, float64(telemetry.MemoryAvailable))
	}
	if telemetry.Received != nil && telemetry.Sent != nil {
		w.metric("gtm_host_network_receive_bytes_per_second", "gauge", "Default-route receive rate.", nil, *telemetry.Received)
		w.metric("gtm_host_network_transmit_bytes_per_second", "gauge", "Default-route transmit rate.", nil, *telemetry.Sent)
	}
	w.metric("gtm_notifications_unread", "gauge", "Unread panel notifications.", nil, float64(unread))
	return w.b.String()
}

// prometheus serves the settings actions and the scrape itself.
func (m *Manager) prometheus(r Request) (any, error) {
	if m.Ops == nil || m.Ops.Prometheus == nil {
		return nil, errors.New("metrics export is unavailable on this broker")
	}
	p := m.Ops.Prometheus
	switch r.Action {
	case "prometheus-settings":
		return p.View(), nil
	case "prometheus-configure":
		return p.Configure(r.Prometheus)
	}
	if !p.Allowed(r.Prometheus.Token) {
		return nil, errors.New("unauthorized")
	}
	view := m.Ops.Health.View(time.Now().UTC(), time.UTC)
	var traffic *MetricsView
	if m.Metrics != nil {
		v := m.Metrics.View()
		traffic = &v
	}
	unread := 0
	if m.Ops.Notify != nil {
		unread = m.Ops.Notify.View().Unread
	}
	host, _ := os.Hostname()
	return prometheusText(host, &view, traffic, m.telemetry.Sample(), unread), nil
}
