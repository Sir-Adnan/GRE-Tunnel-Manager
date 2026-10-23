package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
)

const metricsTable = "gtm_panel_metrics"

type MetricsSettings struct {
	Enabled        bool     `json:"enabled"`
	Interval       int      `json:"interval"`
	IDs            []string `json:"ids"`
	RetentionHours int      `json:"retention_hours,omitempty"`
}
type Traffic struct {
	Received         uint64    `json:"received"`
	Sent             uint64    `json:"sent"`
	LastReceived     uint64    `json:"last_received"`
	LastSent         uint64    `json:"last_sent"`
	Updated          time.Time `json:"updated"`
	Source           string    `json:"source"`
	CycleStart       time.Time `json:"cycle_start,omitempty"`
	BaselineReceived uint64    `json:"baseline_received,omitempty"`
	BaselineSent     uint64    `json:"baseline_sent,omitempty"`
}
type MetricsView struct {
	Settings MetricsSettings           `json:"settings"`
	Counters map[string]Traffic        `json:"counters"`
	Since    time.Time                 `json:"since"`
	Error    string                    `json:"error,omitempty"`
	Revision uint64                    `json:"revision"`
	Policies map[string]TrafficPolicy  `json:"policies"`
	History  map[string][]TrafficPoint `json:"history,omitempty"`
	Cycles   map[string][]TrafficCycle `json:"cycles,omitempty"`
}
type Metrics struct {
	mu        sync.Mutex
	Runner    Runner
	Path      string
	view      MetricsView
	signature string
	nftActive bool
}

func NewMetrics(r Runner, path string) (*Metrics, error) {
	m := &Metrics{Runner: r, Path: path, view: MetricsView{Settings: MetricsSettings{Interval: 60, IDs: []string{}}, Counters: map[string]Traffic{}, Since: time.Now().UTC()}}
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return nil, errors.New("traffic ledger must be a regular file")
	}
	f, e := os.Open(path)
	var data []byte
	if e == nil {
		data, e = io.ReadAll(io.LimitReader(f, 16*1024*1024+1))
		_ = f.Close()
		if len(data) > 16*1024*1024 {
			return nil, errors.New("traffic ledger exceeds size limit")
		}
	}
	if e == nil {
		if e = json.Unmarshal(data, &m.view); e != nil {
			return nil, e
		}
		if m.view.Counters == nil {
			m.view.Counters = map[string]Traffic{}
		}
		if e = metricsValid(m.view.Settings); e != nil {
			return nil, e
		}
	} else if !os.IsNotExist(e) {
		return nil, e
	}
	if e = m.validateLedger(); e != nil {
		return nil, e
	}
	// Kernel counters do not survive every reboot/reload. Establish a new baseline
	// on first reconciliation; lifetime totals are never replaced by raw samples.
	m.nftActive = m.view.Settings.Enabled
	return m, nil
}
func metricsValid(s MetricsSettings) error {
	if s.Interval < 15 || s.Interval > 3600 || len(s.IDs) > 128 || s.RetentionHours < 0 || s.RetentionHours > 720 {
		return errors.New("metrics interval must be 15–3600 seconds, with at most 128 selections")
	}
	return nil
}
func (m *Metrics) View() MetricsView {
	m.mu.Lock()
	defer m.mu.Unlock()
	view := Metrics{view: cloneMetrics(m.view)}
	view.trimHistory(time.Now().UTC())
	return view.view
}
func (m *Metrics) save() error {
	if e := os.MkdirAll(filepath.Dir(m.Path), 0700); e != nil {
		return e
	}
	return config.Save(m.Path, m.view, 0600)
}
func wanted(ids []string, id string) bool {
	if len(ids) == 0 {
		return true
	}
	for _, v := range ids {
		if v == id {
			return true
		}
	}
	return false
}
func (m *Metrics) Configure(ctx context.Context, s MetricsSettings, inventory Inventory, expectedRevision ...uint64) (MetricsView, error) {
	if e := metricsValid(s); e != nil {
		return MetricsView{}, e
	}
	available := map[string]bool{}
	for _, c := range inventory.Connections {
		available[c.ID] = true
	}
	for _, r := range inventory.Resources {
		available[r.ID] = r.Engine == "gre" || (r.Role == "entrance" && r.Port > 0)
	}
	for _, id := range s.IDs {
		if !available[id] {
			return MetricsView{}, errors.New("unsupported or missing metrics selection")
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(expectedRevision) > 0 && expectedRevision[0] != m.view.Revision {
		return MetricsView{}, errors.New("traffic settings changed; refresh before saving")
	}
	if s.Enabled {
		if e := m.checkCapacity(s, inventory); e != nil {
			return MetricsView{}, e
		}
	}
	old := m.view.Settings
	previous := cloneMetrics(m.view)
	if old.Enabled {
		if e := m.collect(ctx); e != nil {
			if s.Enabled {
				return MetricsView{}, e
			}
		}
		m.sampleInterfaces(inventory, false)
	}
	m.view.Settings = s
	m.view.Revision++
	m.trimHistory(time.Now().UTC())
	m.signature = ""
	if e := m.save(); e != nil {
		m.view = previous
		return MetricsView{}, e
	}
	if e := m.reconcile(ctx, inventory); e != nil {
		m.view = previous
		m.signature = ""
		if recovery := m.save(); recovery != nil {
			return MetricsView{}, fmt.Errorf("%w; metrics settings recovery failed: %v", e, recovery)
		}
		return MetricsView{}, e
	}
	if s.Enabled {
		m.sampleInterfaces(inventory, true)
	}
	if e := m.save(); e != nil {
		return MetricsView{}, e
	}
	return cloneMetrics(m.view), nil
}
func MetricsRules(inventory Inventory, s MetricsSettings) string {
	var definitions, input, output, forward strings.Builder
	counter := func(id string) { fmt.Fprintf(&definitions, "counter %s_rx {}\ncounter %s_tx {}\n", id, id) }
	match := func(bind string, port string, protocol string, interfaceName string) (string, string) {
		family := "ip"
		if strings.Contains(bind, ":") {
			family = "ip6"
		}
		proto := "meta l4proto " + protocol
		if protocol == "both" {
			proto = "meta l4proto { tcp, udp }"
		}
		incoming, outgoing := proto+" ", proto+" "
		if bind != "0.0.0.0" && bind != "::" {
			incoming += family + " daddr " + bind + " "
			outgoing += family + " saddr " + bind + " "
		}
		incoming += "th dport " + port + " "
		outgoing += "th sport " + port + " "
		_ = interfaceName
		return incoming, outgoing
	}
	for _, c := range inventory.Connections {
		if !c.Enabled || !wanted(s.IDs, c.ID) {
			continue
		}
		counter(c.ID)
		if c.Engine == "iptables" || c.Engine == "nftables" {
			family := "ip"
			if strings.Contains(c.Bind, ":") {
				family = "ip6"
			}
			proto := "meta l4proto " + c.Protocol
			if c.Protocol == "both" {
				proto = "meta l4proto { tcp, udp }"
			}
			base := fmt.Sprintf("ct status dnat %s ct original %s daddr %s ct original proto-dst %s ", proto, family, c.Bind, c.Ports)
			entrance, exit := "", ""
			if c.Interface != "any" {
				entrance = "iifname \"" + c.Interface + "\" "
				exit = "oifname \"" + c.Interface + "\" "
			}
			fmt.Fprintf(&forward, "%s%sct direction original counter name %s_rx\n%s%sct direction reply counter name %s_tx\n", base, entrance, c.ID, base, exit, c.ID)
		} else {
			a, b := match(c.Bind, c.Ports, c.Protocol, c.Interface)
			fmt.Fprintf(&input, "%scounter name %s_rx\n", a, c.ID)
			fmt.Fprintf(&output, "%scounter name %s_tx\n", b, c.ID)
		}
	}
	// Reverse public listeners can be measured per public port on the entrance.
	// Destination/control multiplexing is intentionally not guessed from TCP bytes.
	for _, r := range inventory.Resources {
		if r.Role != "entrance" || r.Port < 1 || !wanted(s.IDs, r.ID) {
			continue
		}
		counter(r.ID)
		a, b := match(r.Bind, strconv.Itoa(r.Port), r.Protocol, "any")
		fmt.Fprintf(&input, "%scounter name %s_rx\n", a, r.ID)
		fmt.Fprintf(&output, "%scounter name %s_tx\n", b, r.ID)
	}
	if definitions.Len() == 0 {
		return ""
	}
	return fmt.Sprintf("table inet %s {\n%s chain input { type filter hook input priority 300; policy accept;\n%s }\nchain output { type filter hook output priority 300; policy accept;\n%s }\nchain forward { type filter hook forward priority 300; policy accept;\n%s }\n}\n", metricsTable, definitions.String(), input.String(), output.String(), forward.String())
}
func (m *Metrics) reconcile(ctx context.Context, inventory Inventory) error {
	rules := ""
	if m.view.Settings.Enabled {
		rules = MetricsRules(inventory, m.view.Settings)
	}
	m.nftActive = rules != ""
	signature := rules
	for _, r := range inventory.Resources {
		if r.Engine == "gre" && wanted(m.view.Settings.IDs, r.ID) {
			signature += r.ID + r.Interface
		}
	}
	if signature == m.signature && m.signature != "" {
		return nil
	}
	exists, e := m.Runner.Run(ctx, "nft", []string{"list", "table", "inet", metricsTable}, "")
	_ = exists
	batch := ""
	if e == nil {
		batch = "delete table inet " + metricsTable + "\n"
	}
	batch += rules
	if batch != "" {
		if out, e := m.Runner.Run(ctx, "nft", []string{"--check", "-f", "-"}, batch); e != nil {
			return fmt.Errorf("metrics rules unavailable (install nftables for port accounting): %w: %s", e, out)
		}
		if out, e := m.Runner.Run(ctx, "nft", []string{"-f", "-"}, batch); e != nil {
			return fmt.Errorf("metrics update failed: %w: %s", e, out)
		}
	}
	for id, c := range m.view.Counters {
		if c.Source == "nftables" {
			c.LastReceived = 0
			c.LastSent = 0
			m.view.Counters[id] = c
		}
	}
	m.signature = signature
	if signature == "" {
		m.signature = "disabled"
	}
	return nil
}
func (m *Metrics) collect(ctx context.Context) error {
	if !m.nftActive {
		return nil
	}
	out, e := m.Runner.Run(ctx, "nft", []string{"-j", "list", "table", "inet", metricsTable}, "")
	if e != nil {
		return errors.New("cannot read metrics table; no totals were reset")
	}
	var data struct {
		NFTables []struct {
			Counter *struct {
				Name  string `json:"name"`
				Bytes uint64 `json:"bytes"`
			} `json:"counter"`
		} `json:"nftables"`
	}
	if e = json.Unmarshal([]byte(out), &data); e != nil {
		return e
	}
	now := time.Now().UTC()
	for _, entry := range data.NFTables {
		if entry.Counter == nil {
			continue
		}
		name := entry.Counter.Name
		if !strings.HasSuffix(name, "_rx") && !strings.HasSuffix(name, "_tx") {
			continue
		}
		id := name[:len(name)-3]
		if !trafficID(id) {
			continue
		}
		if _, ok := m.view.Counters[id]; !ok && len(m.view.Counters) >= maxTrafficResources {
			return errors.New("traffic archive full; forget removed resources")
		}
		v := m.view.Counters[id]
		sample := entry.Counter.Bytes
		v.Source = "nftables"
		v.Updated = now
		if strings.HasSuffix(name, "_rx") {
			v.Received = addTraffic(v.Received, delta(sample, v.LastReceived))
			v.LastReceived = sample
		} else {
			v.Sent = addTraffic(v.Sent, delta(sample, v.LastSent))
			v.LastSent = sample
		}
		m.view.Counters[id] = v
	}
	return nil
}
func delta(sample, last uint64) uint64 {
	if sample >= last {
		return sample - last
	}
	return sample
}
func (m *Metrics) Tick(ctx context.Context, inventory Inventory) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.view.Settings.Enabled {
		return nil
	}
	if e := m.checkCapacity(m.view.Settings, inventory); e != nil {
		m.view.Error = e.Error()
		return e
	}
	if e := m.collect(ctx); e != nil {
		m.signature = ""
	}
	if e := m.reconcile(ctx, inventory); e != nil {
		m.view.Error = e.Error()
		return e
	}
	if e := m.collect(ctx); e != nil {
		m.view.Error = e.Error()
		return e
	}
	m.sampleInterfaces(inventory, false)
	m.view.Error = ""
	m.recordHistory(time.Now().UTC())
	return m.save()
}
func (m *Metrics) sampleInterfaces(inventory Inventory, baseline bool) {
	for _, r := range inventory.Resources {
		if r.Engine != "gre" || !wanted(m.view.Settings.IDs, r.ID) {
			continue
		}
		rx, e1 := os.ReadFile("/sys/class/net/" + r.Interface + "/statistics/rx_bytes")
		tx, e2 := os.ReadFile("/sys/class/net/" + r.Interface + "/statistics/tx_bytes")
		if e1 != nil || e2 != nil {
			continue
		}
		a, e1 := strconv.ParseUint(strings.TrimSpace(string(rx)), 10, 64)
		b, e2 := strconv.ParseUint(strings.TrimSpace(string(tx)), 10, 64)
		if e1 != nil || e2 != nil {
			continue
		}
		v := m.view.Counters[r.ID]
		if _, ok := m.view.Counters[r.ID]; !ok && len(m.view.Counters) >= maxTrafficResources {
			continue
		}
		if v.Source == "" || baseline {
			v.LastReceived = a
			v.LastSent = b
		}
		v.Received = addTraffic(v.Received, delta(a, v.LastReceived))
		v.Sent = addTraffic(v.Sent, delta(b, v.LastSent))
		v.LastReceived = a
		v.LastSent = b
		v.Source = "interface"
		v.Updated = time.Now().UTC()
		m.view.Counters[r.ID] = v
	}
}
func (m *Metrics) Enabled() bool { m.mu.Lock(); defer m.mu.Unlock(); return m.view.Settings.Enabled }
func (m *Metrics) Interval() int { m.mu.Lock(); defer m.mu.Unlock(); return m.view.Settings.Interval }
