package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

const TrafficProtocol = 1
const MaxTraffic = 65536

// TrafficReport intentionally excludes customer labels, policies, raw counters,
// retained histories and local error strings. Inventory supplies display names.
type TrafficReport struct {
	Protocol int                       `json:"protocol"`
	Enabled  bool                      `json:"enabled"`
	Interval int                       `json:"interval"`
	Since    time.Time                 `json:"since"`
	Counters map[string]TrafficCounter `json:"counters"`
	Failure  string                    `json:"failure,omitempty"`
}

type TrafficCounter struct {
	Received      uint64    `json:"received"`
	Sent          uint64    `json:"sent"`
	CycleReceived uint64    `json:"cycle_received"`
	CycleSent     uint64    `json:"cycle_sent"`
	CycleStart    time.Time `json:"cycle_start"`
	Updated       time.Time `json:"updated"`
	Source        string    `json:"source"`
}

type TrafficView struct {
	NodeID   string         `json:"node_id"`
	Status   string         `json:"status"`
	Observed *time.Time     `json:"observed,omitempty"`
	Summary  *TrafficReport `json:"summary,omitempty"`
}

type trafficObservation struct {
	summary  TrafficReport
	seen     time.Time
	observed *time.Time
}

func (r TrafficReport) validate() error {
	if r.Protocol != TrafficProtocol || r.Interval < 15 || r.Interval > 3600 || len(r.Counters) > 128 || r.Since.IsZero() {
		return errors.New("invalid traffic summary contract")
	}
	if r.Failure != "" && r.Failure != "collection_unavailable" && r.Failure != "summary_unavailable" {
		return errors.New("invalid traffic failure")
	}
	for id, c := range r.Counters {
		if !(model.IDPattern.MatchString(id) || (control.ServiceOK(id) && !strings.HasPrefix(id, "gtm-F"))) || c.CycleReceived > c.Received || c.CycleSent > c.Sent || c.Updated.IsZero() || (c.Source != "nftables" && c.Source != "interface") {
			return errors.New("invalid traffic counter")
		}
	}
	return nil
}

func readTraffic(ctx context.Context, client control.Client) TrafficReport {
	r := TrafficReport{Protocol: TrafficProtocol, Interval: 60, Since: time.Now().UTC(), Counters: map[string]TrafficCounter{}, Failure: "summary_unavailable"}
	raw, e := client.Do(ctx, control.Request{Action: "metrics"})
	var v control.MetricsView
	if e != nil || len(raw) > 262144 || json.Unmarshal(raw, &v) != nil {
		return r
	}
	r.Enabled, r.Interval, r.Since, r.Failure = v.Settings.Enabled, v.Settings.Interval, v.Since, ""
	if v.Error != "" {
		r.Failure = "collection_unavailable"
	}
	for id, c := range v.Counters {
		if c.BaselineReceived > c.Received || c.BaselineSent > c.Sent {
			r.Failure = "summary_unavailable"
			r.Counters = map[string]TrafficCounter{}
			return r
		}
		r.Counters[id] = TrafficCounter{Received: c.Received, Sent: c.Sent, CycleReceived: c.Received - c.BaselineReceived, CycleSent: c.Sent - c.BaselineSent, CycleStart: c.CycleStart, Updated: c.Updated, Source: c.Source}
	}
	if r.validate() != nil {
		return TrafficReport{Protocol: TrafficProtocol, Interval: 60, Since: time.Now().UTC(), Counters: map[string]TrafficCounter{}, Failure: "summary_unavailable"}
	}
	return r
}

func (h *Hub) serveTraffic(w http.ResponseWriter, r *http.Request) {
	if len(r.TLS.VerifiedChains) == 0 || len(r.TLS.PeerCertificates) == 0 {
		nodeError(w, 403, problem("identity_required", "A trusted node certificate is required"))
		return
	}
	crt := r.TLS.PeerCertificates[0]
	h.mu.Lock()
	_, e := h.identify(crt)
	h.mu.Unlock()
	if e != nil {
		nodeError(w, 403, e)
		return
	}
	var summary TrafficReport
	if !nodeDecode(w, r, MaxTraffic, &summary) {
		return
	}
	if e = summary.validate(); e != nil {
		nodeError(w, 400, problem("invalid_traffic", "Invalid bounded traffic summary"))
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if _, e = h.identify(crt); e != nil {
		nodeError(w, 403, e)
		return
	}
	now := h.now()
	o := trafficObservation{summary: summary, seen: now, observed: &now}
	if summary.Failure == "summary_unavailable" {
		o.observed = nil
		if previous, ok := h.traffic[crt.Subject.CommonName]; ok {
			o.summary = previous.summary
			o.summary.Failure = summary.Failure
			o.observed = previous.observed
		}
	}
	h.traffic[crt.Subject.CommonName] = o
	nodeReply(w, 200, map[string]int{"protocol": TrafficProtocol})
}

// Traffic returns only one identity's last snapshot. It never contacts a Node or
// sums counters across overlapping forwarding and GRE measurement paths.
func (h *Hub) Traffic(id string) (TrafficView, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	v := TrafficView{NodeID: id, Status: "waiting"}
	for _, n := range h.state.Nodes {
		if n.ID != id {
			continue
		}
		if n.Revoked {
			v.Status = "revoked"
			return v, nil
		}
		if o, ok := h.traffic[id]; ok {
			copy := o.summary
			copy.Counters = make(map[string]TrafficCounter, len(o.summary.Counters))
			for k, c := range o.summary.Counters {
				copy.Counters[k] = c
			}
			v.Summary, v.Status = &copy, "online"
			if o.observed != nil {
				observed := *o.observed
				v.Observed = &observed
			}
			if copy.Failure != "" {
				v.Status = "degraded"
			}
			if h.now().Sub(o.seen) > 3*time.Minute {
				v.Status = "offline"
			}
		}
		return v, nil
	}
	return v, problem("not_found", "Node not found")
}
