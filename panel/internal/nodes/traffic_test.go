package nodes

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

func trafficSample() TrafficReport {
	now := time.Now().UTC()
	return TrafficReport{Protocol: 1, Enabled: true, Interval: 60, Since: now, Counters: map[string]TrafficCounter{"F000001": {Received: 120, Sent: 50, CycleReceived: 20, CycleSent: 10, Updated: now, CycleStart: now, Source: "nftables"}}}
}

func TestRemoteInventoryOmitsPresentationCatalog(t *testing.T) {
	raw, e := control.NewDemo().Do(context.Background(), control.Request{Action: "inventory"})
	if e != nil {
		t.Fatal(e)
	}
	var inv control.Inventory
	json.Unmarshal(raw, &inv)
	if len(inv.Presets) == 0 {
		t.Fatal("local catalog missing")
	}
	canonical, e := canonicalInventory(raw)
	if e != nil {
		t.Fatal(e)
	}
	inv.Presets[0].Label["en"] = "Different UI copy"
	changed, _ := json.Marshal(inv)
	other, e := canonicalInventory(changed)
	if e != nil || string(canonical) != string(other) || strings.Contains(string(canonical), `"presets"`) {
		t.Fatal("UI catalog affects Node inventory/revision")
	}
}

func TestTrafficIdentityIsolationStalenessFailureAndRevocation(t *testing.T) {
	f := newFixture(t)
	a, _ := f.enroll(t, "One")
	b, _ := f.enroll(t, "Two")
	c := transport(client(t, a))
	defer c.CloseIdleConnections()
	var ack any
	if e := post(context.Background(), c, f.s.URL+"/v1/traffic", trafficSample(), &ack); e != nil {
		t.Fatal(e)
	}
	v, e := f.h.Traffic(a.ID)
	if e != nil || v.Status != "online" || v.Summary.Counters["F000001"].CycleReceived != 20 {
		t.Fatal(v, e)
	}
	observed := *v.Observed
	v.Summary.Counters["F000001"] = TrafficCounter{}
	v, _ = f.h.Traffic(a.ID)
	if v.Summary.Counters["F000001"].Received != 120 {
		t.Fatal("cache escaped by reference")
	}
	vb, _ := f.h.Traffic(b.ID)
	if vb.Summary != nil || vb.Status != "waiting" {
		t.Fatal("another identity received traffic", vb)
	}
	if _, e = f.h.Traffic("../../file"); e == nil {
		t.Fatal("invalid identity accepted")
	}
	r := trafficSample()
	r.Failure = "summary_unavailable"
	r.Counters = map[string]TrafficCounter{}
	if e = post(context.Background(), c, f.s.URL+"/v1/traffic", r, &ack); e != nil {
		t.Fatal(e)
	}
	v, _ = f.h.Traffic(a.ID)
	if v.Status != "degraded" || !v.Observed.Equal(observed) || v.Summary.Counters["F000001"].Received != 120 {
		t.Fatal("failed read replaced known totals", v)
	}
	f.h.mu.Lock()
	f.h.now = func() time.Time { return time.Now().Add(4 * time.Minute) }
	f.h.mu.Unlock()
	v, _ = f.h.Traffic(a.ID)
	if v.Status != "offline" {
		t.Fatal("stale summary remains live")
	}
	n := f.h.Views().Nodes[0]
	if e = f.h.Revoke(n.ID, n.Revision); e != nil {
		t.Fatal(e)
	}
	v, _ = f.h.Traffic(a.ID)
	if v.Status != "revoked" || v.Summary != nil {
		t.Fatal("revoked snapshot still exposed")
	}
	if e = post(context.Background(), c, f.s.URL+"/v1/traffic", trafficSample(), &ack); e == nil || !fatal(e) {
		t.Fatal("revocation ignored on existing TLS connection", e)
	}
}

func TestTrafficClosedBoundedContractAndInventoryCompatibility(t *testing.T) {
	f := newFixture(t)
	id, _ := f.enroll(t, "One")
	c := transport(client(t, id))
	defer c.CloseIdleConnections()
	var ack any
	for _, bad := range []func(*TrafficReport){
		func(r *TrafficReport) { r.Protocol = 2 },
		func(r *TrafficReport) { r.Interval = 1 },
		func(r *TrafficReport) { r.Failure = "private /etc/path" },
		func(r *TrafficReport) { r.Counters["bad;command"] = r.Counters["F000001"] },
		func(r *TrafficReport) { v := r.Counters["F000001"]; v.CycleReceived = 121; r.Counters["F000001"] = v },
		func(r *TrafficReport) {
			v := r.Counters["F000001"]
			v.Source = "/private/file"
			r.Counters["F000001"] = v
		},
		func(r *TrafficReport) {
			for i := 1; i <= 129; i++ {
				r.Counters[fmt.Sprintf("F%06d", i)] = r.Counters["F000001"]
			}
		},
	} {
		r := trafficSample()
		bad(&r)
		if e := post(context.Background(), c, f.s.URL+"/v1/traffic", r, &ack); e == nil {
			t.Fatal("invalid report accepted", r)
		}
	}
	for _, body := range []any{map[string]any{"protocol": 1, "extra": "forbidden"}, map[string]any{"padding": strings.Repeat("x", MaxTraffic)}} {
		if e := post(context.Background(), c, f.s.URL+"/v1/traffic", body, &ack); e == nil {
			t.Fatal("unknown/oversized fields accepted")
		}
	}
	tc := client(t, id)
	tc.Certificates = nil
	anonymous := transport(tc)
	defer anonymous.CloseIdleConnections()
	if e := post(context.Background(), anonymous, f.s.URL+"/v1/traffic", trafficSample(), &ack); e == nil {
		t.Fatal("anonymous report accepted")
	}
	if e := send(t, f, id, sample(t)); e != nil {
		t.Fatal("old inventory report became incompatible", e)
	}
	if v, _ := f.h.Traffic(id.ID); v.Summary != nil {
		t.Fatal("inventory enabled traffic implicitly")
	}
}

type trafficClient struct {
	control.Client
	raw json.RawMessage
}

func (c trafficClient) Do(ctx context.Context, r control.Request) (json.RawMessage, error) {
	if r.Action == "metrics" {
		return c.raw, nil
	}
	return c.Client.Do(ctx, r)
}

func TestTrafficProjectionPrivacyAndOptionalAgentDelivery(t *testing.T) {
	now := time.Now().UTC()
	v := control.MetricsView{Settings: control.MetricsSettings{Enabled: true, Interval: 60}, Since: now, Error: "secret local path", Counters: map[string]control.Traffic{"F000001": {Received: 120, Sent: 50, BaselineReceived: 100, BaselineSent: 40, Updated: now, Source: "nftables"}}, Policies: map[string]control.TrafficPolicy{"F000001": {Label: "private customer", Limit: 123}}}
	raw, _ := json.Marshal(v)
	c := trafficClient{Client: control.NewDemo(), raw: raw}
	r := readTraffic(context.Background(), c)
	b, _ := json.Marshal(r)
	if strings.Contains(string(b), "secret") || strings.Contains(string(b), "customer") || strings.Contains(string(b), "baseline") || r.Failure != "collection_unavailable" || r.Counters["F000001"].CycleReceived != 20 {
		t.Fatal(string(b))
	}
	f := newFixture(t)
	id, path := f.enroll(t, "Agent")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- (Agent{Path: path, Version: "1.3.0", Client: c, Traffic: true}).Run(ctx) }()
	deadline := time.After(5 * time.Second)
	for {
		v, _ := f.h.Traffic(id.ID)
		if v.Summary != nil {
			break
		}
		select {
		case e := <-done:
			t.Fatal("Agent stopped", e)
		case <-deadline:
			t.Fatal("Agent did not deliver traffic")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	if e := <-done; e != nil {
		t.Fatal(e)
	}
	if f.h.Views().Nodes[0].Status != "online" {
		t.Fatal("traffic replaced inventory")
	}
	f.h.Close()
	restarted, e := Open(f.dir)
	if e != nil {
		t.Fatal(e)
	}
	defer restarted.Close()
	if v, _ := restarted.Traffic(id.ID); v.Summary != nil || v.Status != "waiting" {
		t.Fatal("Controller persisted traffic snapshots")
	}
}

func TestTrafficExpiredIdentityAndOlderController(t *testing.T) {
	t.Run("expiry on reused TLS connection", func(t *testing.T) {
		f := newFixture(t)
		id, _ := f.enroll(t, "Expiry")
		c := transport(client(t, id))
		defer c.CloseIdleConnections()
		var ack any
		if e := post(context.Background(), c, f.s.URL+"/v1/traffic", trafficSample(), &ack); e != nil {
			t.Fatal(e)
		}
		f.h.mu.Lock()
		f.h.now = func() time.Time { return time.Now().Add(31 * 24 * time.Hour) }
		f.h.mu.Unlock()
		if e := post(context.Background(), c, f.s.URL+"/v1/traffic", trafficSample(), &ack); e == nil || !fatal(e) {
			t.Fatal("expired traffic identity accepted", e)
		}
	})
	t.Run("optional endpoint does not stop old inventory", func(t *testing.T) {
		f := newFixture(t)
		f.noTraffic.Store(true)
		id, path := f.enroll(t, "Old Controller")
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		notified := make(chan string, 4)
		done := make(chan error, 1)
		go func() {
			done <- (Agent{Path: path, Version: "1.3.0", Traffic: true, Client: control.NewDemo(), Notify: func(code string) { notified <- code }}).Run(ctx)
		}()
		select {
		case code := <-notified:
			if code != "traffic_report_unavailable" {
				t.Fatal(code)
			}
		case e := <-done:
			t.Fatal("optional report stopped Agent", e)
		case <-time.After(5 * time.Second):
			t.Fatal("missing optional-report result")
		}
		if f.h.Views().Nodes[0].Status != "online" {
			t.Fatal("old inventory no longer online")
		}
		if v, _ := f.h.Traffic(id.ID); v.Summary != nil {
			t.Fatal("unsupported Controller retained traffic")
		}
		cancel()
		if e := <-done; e != nil {
			t.Fatal(e)
		}
	})
}
