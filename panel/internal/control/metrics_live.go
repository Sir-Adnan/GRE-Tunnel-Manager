package control

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"
	"time"
)

// Live per-connection rates, read on demand from the counters usage
// collection already keeps (nftables named counters and GRE interface
// statistics). Nothing runs in the background: an open page asks, several
// viewers share one sample, and a counter that went backwards (a rules reload,
// an interface restart) starts a new baseline instead of a spike.

// LiveRate is one connection's current throughput in bytes per second.
type LiveRate struct {
	Received float64 `json:"received_per_second"`
	Sent     float64 `json:"sent_per_second"`
}

// TrafficLive is one sample of every collected connection's throughput.
type TrafficLive struct {
	Time time.Time `json:"time"`
	// Window is 0 for the first sample after start or a pause: rates need two.
	Window  float64             `json:"window_seconds"`
	Enabled bool                `json:"enabled"`
	Rates   map[string]LiveRate `json:"rates"`
	Error   string              `json:"error,omitempty"`
}

type liveState struct {
	time  time.Time
	bytes map[string]netBytes
	view  TrafficLive
}

// Live returns the current rates; see liveAt.
func (m *Metrics) Live(ctx context.Context) TrafficLive {
	return m.liveAt(ctx, time.Now().UTC(), readKernelFile)
}

func (m *Metrics) liveAt(ctx context.Context, now time.Time, read func(string) ([]byte, error)) TrafficLive {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := &m.live
	if !s.view.Time.IsZero() && now.Sub(s.view.Time) >= 0 && now.Sub(s.view.Time) < 900*time.Millisecond {
		return s.view
	}
	v := TrafficLive{Time: now, Enabled: m.view.Settings.Enabled, Rates: map[string]LiveRate{}}
	if !v.Enabled {
		*s = liveState{view: v}
		return v
	}
	next := map[string]netBytes{}
	if m.nftActive && m.Runner != nil {
		out, e := m.Runner.Run(ctx, "nft", []string{"-j", "list", "table", "inet", metricsTable}, "")
		var counters map[string]uint64
		if e == nil {
			counters, e = nftCounters(out)
		}
		if e != nil {
			v.Error = "traffic counters unavailable"
		}
		for name, value := range counters {
			id, rx := strings.CutSuffix(name, "_rx")
			if !rx {
				var tx bool
				if id, tx = strings.CutSuffix(name, "_tx"); !tx {
					continue
				}
			}
			if !trafficID(id) {
				continue
			}
			c := next[id]
			if rx {
				c.rx = value
			} else {
				c.tx = value
			}
			next[id] = c
		}
	}
	for id, iface := range m.liveInterfaces {
		if c, ok := interfaceCounters(iface, read); ok {
			next[id] = c
		}
	}
	window := now.Sub(s.time).Seconds()
	if !s.time.IsZero() && window >= 0.9 && window <= 30 {
		v.Window = window
		for id, c := range next {
			old, ok := s.bytes[id]
			if !ok || c.rx < old.rx || c.tx < old.tx {
				continue
			}
			v.Rates[id] = LiveRate{Received: float64(c.rx-old.rx) / window, Sent: float64(c.tx-old.tx) / window}
		}
	}
	*s = liveState{time: now, bytes: next, view: v}
	return v
}

// nftCounters maps every named counter in an `nft -j list` document to its bytes.
func nftCounters(out string) (map[string]uint64, error) {
	var data struct {
		NFTables []struct {
			Counter *struct {
				Name  string `json:"name"`
				Bytes uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if e := json.Unmarshal([]byte(out), &data); e != nil {
		return nil, e
	}
	counters := map[string]uint64{}
	for _, entry := range data.NFTables {
		if entry.Counter != nil {
			counters[entry.Counter.Name] = entry.Counter.Bytes
		}
	}
	return counters, nil
}

// interfaceCounters reads a GRE interface's byte counters from sysfs.
func interfaceCounters(iface string, read func(string) ([]byte, error)) (netBytes, bool) {
	if !modelInterface(iface) {
		return netBytes{}, false
	}
	value := func(name string) (uint64, bool) {
		b, e := read("/sys/class/net/" + iface + "/statistics/" + name)
		if e != nil {
			return 0, false
		}
		n, e := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
		return n, e == nil
	}
	rx, ok1 := value("rx_bytes")
	tx, ok2 := value("tx_bytes")
	return netBytes{rx: rx, tx: tx}, ok1 && ok2
}

// rememberInterfaces keeps the collected GRE interfaces for Live, which must
// not rebuild the inventory on every request. Called with m.mu held.
func (m *Metrics) rememberInterfaces(inventory Inventory) {
	m.liveInterfaces = map[string]string{}
	if !m.view.Settings.Enabled {
		return
	}
	for _, r := range inventory.Resources {
		if r.Engine == "gre" && wanted(m.view.Settings.IDs, r.ID) && modelInterface(r.Interface) {
			m.liveInterfaces[r.ID] = r.Interface
		}
	}
}
