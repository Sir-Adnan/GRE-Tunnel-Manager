package control

import (
	"context"
	"errors"
	"maps"
	"math"
	"slices"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

const maxTrafficResources = 128
const maxTrafficPoints = 288
const maxTrafficCycles = 12
const maxTrafficBytes = uint64(9007199254740991) // exact in browser JSON numbers

// Quotas are advisory. No asynchronous process may silently change the network.
type TrafficPolicy struct {
	Label     string `json:"label"`
	Limit     uint64 `json:"limit"`
	Direction string `json:"direction"` // total, received, sent
}
type TrafficPoint struct {
	Time       time.Time `json:"time"`
	Received   uint64    `json:"received"`
	Sent       uint64    `json:"sent"`
	CycleStart time.Time `json:"cycle_start"`
}
type TrafficCycle struct {
	Start    time.Time `json:"start"`
	End      time.Time `json:"end"`
	Received uint64    `json:"received"`
	Sent     uint64    `json:"sent"`
	Label    string    `json:"label,omitempty"`
}
type TrafficChange struct {
	ID       string        `json:"id"`
	Revision uint64        `json:"revision"`
	Policy   TrafficPolicy `json:"policy"`
}
type TrafficArchive struct {
	ID      string         `json:"id"`
	History []TrafficPoint `json:"history"`
	Cycles  []TrafficCycle `json:"cycles"`
}

func (m *Metrics) Summary() MetricsView {
	m.mu.Lock()
	defer m.mu.Unlock()
	v := m.view
	v.History = nil
	v.Cycles = nil
	return cloneMetrics(v)
}
func (m *Metrics) Archive(id string) (TrafficArchive, error) {
	if !trafficID(id) {
		return TrafficArchive{}, errors.New("invalid traffic resource")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	v := Metrics{view: MetricsView{Settings: m.view.Settings, History: map[string][]TrafficPoint{id: slices.Clone(m.view.History[id])}}}
	v.trimHistory(time.Now().UTC())
	return TrafficArchive{ID: id, History: append([]TrafficPoint{}, v.view.History[id]...), Cycles: append([]TrafficCycle{}, m.view.Cycles[id]...)}, nil
}
func trafficReceipt(v MetricsView, e error) (any, error) {
	if e != nil {
		return nil, e
	}
	return map[string]any{"ok": true, "revision": v.Revision}, nil
}

func trafficID(id string) bool {
	return model.IDPattern.MatchString(id) || (ServiceOK(id) && !strings.HasPrefix(id, "gtm-F"))
}
func validTrafficPolicy(p TrafficPolicy) bool {
	if !utf8.ValidString(p.Label) || utf8.RuneCountInString(p.Label) > 80 || p.Limit > maxTrafficBytes || !oneOf(p.Direction, "total", "received", "sent") {
		return false
	}
	for _, r := range p.Label {
		if unicode.IsControl(r) || (unicode.In(r, unicode.Cf) && r != '\u200c' && r != '\u200d') {
			return false
		}
	}
	return true
}
func cloneMetrics(v MetricsView) MetricsView {
	next := v
	next.Settings.IDs = append([]string{}, v.Settings.IDs...)
	next.Counters = maps.Clone(v.Counters)
	next.Policies = maps.Clone(v.Policies)
	next.History = make(map[string][]TrafficPoint, len(v.History))
	for id, points := range v.History {
		next.History[id] = slices.Clone(points)
	}
	next.Cycles = make(map[string][]TrafficCycle, len(v.Cycles))
	for id, cycles := range v.Cycles {
		next.Cycles[id] = slices.Clone(cycles)
	}
	return next
}
func (m *Metrics) validateLedger() error {
	if len(m.view.Counters) > maxTrafficResources || len(m.view.Policies) > maxTrafficResources || len(m.view.History) > maxTrafficResources || len(m.view.Cycles) > maxTrafficResources {
		return errors.New("traffic ledger resource limit exceeded")
	}
	if m.view.Policies == nil {
		m.view.Policies = map[string]TrafficPolicy{}
	}
	if m.view.History == nil {
		m.view.History = map[string][]TrafficPoint{}
	}
	if m.view.Cycles == nil {
		m.view.Cycles = map[string][]TrafficCycle{}
	}
	for id, c := range m.view.Counters {
		if !trafficID(id) || c.BaselineReceived > c.Received || c.BaselineSent > c.Sent {
			return errors.New("invalid traffic baseline")
		}
	}
	for id, p := range m.view.Policies {
		if !trafficID(id) || !validTrafficPolicy(p) {
			return errors.New("invalid traffic policy")
		}
	}
	for id, points := range m.view.History {
		if !trafficID(id) || len(points) > maxTrafficPoints {
			return errors.New("invalid traffic history")
		}
	}
	for id, cycles := range m.view.Cycles {
		if !trafficID(id) || len(cycles) > maxTrafficCycles {
			return errors.New("invalid traffic cycles")
		}
	}
	m.trimHistory(time.Now().UTC())
	return nil
}
func trafficAvailable(inventory Inventory, id string) bool {
	for _, c := range inventory.Connections {
		if c.ID == id {
			return true
		}
	}
	for _, r := range inventory.Resources {
		if r.ID == id && (r.Engine == "gre" || (r.Role == "entrance" && r.Port > 0)) {
			return true
		}
	}
	return false
}
func (m *Metrics) checkCapacity(s MetricsSettings, inventory Inventory) error {
	ids := map[string]bool{}
	for id := range m.view.Counters {
		ids[id] = true
	}
	for _, c := range inventory.Connections {
		if c.Enabled && wanted(s.IDs, c.ID) {
			ids[c.ID] = true
		}
	}
	for _, r := range inventory.Resources {
		if (r.Engine == "gre" || (r.Role == "entrance" && r.Port > 0)) && wanted(s.IDs, r.ID) {
			ids[r.ID] = true
		}
	}
	if len(ids) > maxTrafficResources {
		return errors.New("traffic archive capacity reached (128 resources); forget removed entries or track fewer connections")
	}
	return nil
}
func (m *Metrics) Change(ctx context.Context, action string, change TrafficChange, inventory Inventory) (MetricsView, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if change.Revision != m.view.Revision {
		return MetricsView{}, errors.New("traffic settings changed; refresh before continuing")
	}
	if !trafficID(change.ID) || !oneOf(action, "metrics-reset", "metrics-policy", "metrics-forget") {
		return MetricsView{}, errors.New("invalid traffic operation")
	}
	_, known := m.view.Counters[change.ID]
	_, policyKnown := m.view.Policies[change.ID]
	known = known || policyKnown
	available := trafficAvailable(inventory, change.ID)
	if !known && !available {
		return MetricsView{}, errors.New("traffic resource not found")
	}
	if action == "metrics-forget" && available {
		return MetricsView{}, errors.New("remove the connection before forgetting its archived accounting")
	}
	if action == "metrics-policy" && !validTrafficPolicy(change.Policy) {
		return MetricsView{}, errors.New("invalid traffic label, quota or direction")
	}
	old := cloneMetrics(m.view)
	rollback := func(e error) (MetricsView, error) { m.view = old; return MetricsView{}, e }
	// Capture in-flight bytes BEFORE moving the baseline, never zero kernel counters.
	if action == "metrics-reset" && m.view.Settings.Enabled {
		if e := m.collect(ctx); e != nil {
			return rollback(e)
		}
		m.sampleInterfaces(inventory, false)
	}
	if !known && len(m.view.Counters) >= maxTrafficResources {
		return rollback(errors.New("archive limit reached; forget removed resources first"))
	}
	m.applyTrafficChange(action, change, time.Now().UTC())
	m.view.Revision++
	if e := m.validateLedger(); e != nil {
		return rollback(e)
	}
	if e := m.save(); e != nil {
		return rollback(e)
	}
	return cloneMetrics(m.view), nil
}
func (m *Metrics) trimHistory(now time.Time) {
	if m.view.Settings.RetentionHours == 0 {
		m.view.History = map[string][]TrafficPoint{}
		return
	}
	cutoff := now.Add(-time.Duration(m.view.Settings.RetentionHours) * time.Hour)
	for id, points := range m.view.History {
		kept := make([]TrafficPoint, 0, len(points))
		for _, p := range points {
			if !p.Time.Before(cutoff) && !p.Time.After(now) {
				kept = append(kept, p)
			}
		}
		if len(kept) > maxTrafficPoints {
			kept = kept[len(kept)-maxTrafficPoints:]
		}
		if len(kept) == 0 {
			delete(m.view.History, id)
		} else {
			m.view.History[id] = kept
		}
	}
}
func (m *Metrics) recordHistory(now time.Time) {
	m.trimHistory(now)
	if m.view.Settings.RetentionHours == 0 {
		return
	}
	for id, c := range m.view.Counters {
		if c.Updated.IsZero() || c.Updated.Before(now.Add(-time.Duration(m.view.Settings.Interval)*time.Second)) {
			continue
		}
		points := m.view.History[id]
		if len(points) > 0 && !points[len(points)-1].Time.Before(c.Updated) {
			continue
		}
		start := c.CycleStart
		if start.IsZero() {
			start = m.view.Since
		}
		points = append(points, TrafficPoint{c.Updated, c.Received - c.BaselineReceived, c.Sent - c.BaselineSent, start})
		if len(points) > maxTrafficPoints {
			points = points[len(points)-maxTrafficPoints:]
		}
		m.view.History[id] = points
	}
}
func addTraffic(total, increment uint64) uint64 {
	if increment > math.MaxUint64-total {
		return math.MaxUint64
	}
	return total + increment
}

// Caller validates the resource/revision and holds the owner lock. No I/O.
func (m *Metrics) applyTrafficChange(action string, change TrafficChange, now time.Time) {
	switch action {
	case "metrics-policy":
		m.view.Policies[change.ID] = change.Policy
	case "metrics-forget":
		delete(m.view.Counters, change.ID)
		delete(m.view.Policies, change.ID)
		delete(m.view.History, change.ID)
		delete(m.view.Cycles, change.ID)
	case "metrics-reset":
		c := m.view.Counters[change.ID]
		start := c.CycleStart
		if start.IsZero() {
			start = m.view.Since
		}
		if start.IsZero() {
			start = now
		}
		cycles := append(m.view.Cycles[change.ID], TrafficCycle{Start: start, End: now, Received: c.Received - c.BaselineReceived, Sent: c.Sent - c.BaselineSent, Label: m.view.Policies[change.ID].Label})
		if len(cycles) > maxTrafficCycles {
			cycles = cycles[len(cycles)-maxTrafficCycles:]
		}
		m.view.Cycles[change.ID] = cycles
		c.BaselineReceived = c.Received
		c.BaselineSent = c.Sent
		c.CycleStart = now
		m.view.Counters[change.ID] = c
		delete(m.view.History, change.ID)
	}
}
