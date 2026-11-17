package control

import (
	"hash/fnv"
	"math"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// demoMetrics starts the demo with usage collection on and two days of
// cumulative samples per connection, so the Traffic page has a story to tell.
func demoMetrics(inventory Inventory, now time.Time) MetricsView {
	v := MetricsView{Settings: MetricsSettings{Enabled: true, Interval: 60, IDs: []string{}, RetentionHours: 168}, Counters: map[string]Traffic{}, Since: now.Add(-48 * time.Hour), Policies: map[string]TrafficPolicy{}, History: map[string][]TrafficPoint{}, Cycles: map[string][]TrafficCycle{}}
	ids := []string{}
	for _, c := range inventory.Connections {
		if c.Enabled {
			ids = append(ids, c.ID)
		}
	}
	for _, r := range inventory.Resources {
		if r.Engine == "gre" || (r.Role == "entrance" && r.Port > 0) {
			ids = append(ids, r.ID)
		}
	}
	for _, id := range ids {
		var received, sent float64
		points := []TrafficPoint{}
		for step := 96; step >= 0; step-- {
			at := now.Add(-time.Duration(step) * 30 * time.Minute).Truncate(time.Minute)
			r := demoLive(v.Settings, Inventory{Connections: []model.Connection{{ID: id, Enabled: true}}}, at).Rates[id]
			// Quieter nights: a day curve on top of each connection's own wave.
			day := 0.55 + 0.45*math.Sin(float64(at.Hour()-6)/24*2*math.Pi)
			received += r.Received * day * 1800
			sent += r.Sent * day * 1800
			points = append(points, TrafficPoint{Time: at, Received: uint64(received), Sent: uint64(sent), CycleStart: v.Since})
		}
		v.History[id] = points
		last := points[len(points)-1]
		v.Counters[id] = Traffic{Received: last.Received, Sent: last.Sent, Updated: last.Time, Source: "nftables", CycleStart: v.Since}
	}
	if len(ids) > 0 {
		v.Policies[ids[0]] = TrafficPolicy{Label: "Customer A", Limit: v.Counters[ids[0]].Received * 3 / 2, Direction: "total"}
	}
	return v
}

// demoLive invents smooth, repeatable per-connection rates for the demo: each
// connection gets its own base rate and a slow wave, so the Traffic page and
// connection cards move the way they do on a busy server.
func demoLive(s MetricsSettings, inventory Inventory, now time.Time) TrafficLive {
	v := TrafficLive{Time: now, Window: 2, Enabled: s.Enabled, Rates: map[string]LiveRate{}}
	if !s.Enabled {
		v.Window = 0
		return v
	}
	rate := func(id string) LiveRate {
		h := fnv.New32a()
		_, _ = h.Write([]byte(id))
		seed := float64(h.Sum32()%1000) / 1000
		base := 40e3 + seed*seed*6e6
		t := float64(now.UnixMilli()) / 1000
		wave := 0.65 + 0.35*math.Sin(t/7+seed*6) + 0.12*math.Sin(t/1.7+seed*11)
		down := math.Max(0, base*wave)
		return LiveRate{Received: down, Sent: down * (0.08 + seed*0.2)}
	}
	for _, c := range inventory.Connections {
		if c.Enabled && wanted(s.IDs, c.ID) {
			v.Rates[c.ID] = rate(c.ID)
		}
	}
	for _, r := range inventory.Resources {
		if (r.Engine == "gre" || (r.Role == "entrance" && r.Port > 0)) && wanted(s.IDs, r.ID) {
			v.Rates[r.ID] = rate(r.ID)
		}
	}
	return v
}
