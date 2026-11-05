package health

import (
	"encoding/json"
	"errors"
	"io"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
)

const (
	StatusUp       = "up"
	StatusDegraded = "degraded"
	StatusDown     = "down"
	StatusUnknown  = "unknown"

	KindTCP     = "tcp"
	KindICMP    = "icmp"
	KindService = "service"

	// MaxTargets bounds probe fan-out and the size of the history file.
	MaxTargets   = 128
	recentPoints = 120
	maxOutages   = 1000
	maxFileBytes = 32 * 1024 * 1024
	// saveEvery bounds disk writes when nothing changes state.
	saveEvery = 5 * time.Minute
)

// Target is one probed endpoint. Key is stable across inventory refreshes.
type Target struct {
	Key     string `json:"key"`
	Owner   string `json:"owner"`
	Name    string `json:"name"`
	Engine  string `json:"engine"`
	Kind    string `json:"kind"`
	Address string `json:"address,omitempty"`
	Port    int    `json:"port,omitempty"`
	Unit    string `json:"unit,omitempty"`
}

// Endpoint is the human label of what was probed.
func (t Target) Endpoint() string {
	switch {
	case t.Kind == KindService:
		return t.Unit
	case t.Port > 0 && containsColon(t.Address):
		return "[" + t.Address + "]:" + strconv.Itoa(t.Port)
	case t.Port > 0:
		return t.Address + ":" + strconv.Itoa(t.Port)
	}
	return t.Address
}

func containsColon(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] == ':' {
			return true
		}
	}
	return false
}

// Result is the outcome of one probe.
type Result struct {
	OK    bool    `json:"ok"`
	RTT   float64 `json:"rtt_ms"`
	Error string  `json:"error,omitempty"`
}

// Point is one recent check; R < 0 marks a failed check.
type Point struct {
	T int64   `json:"t"`
	R float64 `json:"r"`
}

type TargetState struct {
	Target
	Status    string    `json:"status"`
	Since     time.Time `json:"since"`
	Checked   time.Time `json:"checked,omitzero"`
	RTT       *float64  `json:"rtt_ms,omitempty"`
	Error     string    `json:"error,omitempty"`
	Fails     int       `json:"fails"`
	Successes int       `json:"successes"`
	FailStart time.Time `json:"fail_start,omitzero"`
	Recent    []Point   `json:"recent"`
}

// Bucket is one hour of checks for one target. Up counts checks whose
// resulting status was not down, so a single lost probe does not cost uptime.
type Bucket struct {
	Hour   int64   `json:"h"`
	Checks int     `json:"n"`
	Up     int     `json:"up"`
	OK     int     `json:"ok"`
	Sum    float64 `json:"sum"`
	Max    float64 `json:"max"`
	Jitter float64 `json:"jit"`
	Pairs  int     `json:"jn"`
}

type Outage struct {
	ID       int64      `json:"id"`
	Key      string     `json:"key"`
	Owner    string     `json:"owner"`
	Name     string     `json:"name"`
	Engine   string     `json:"engine"`
	Endpoint string     `json:"endpoint"`
	Start    time.Time  `json:"start"`
	End      *time.Time `json:"end,omitempty"`
	Reason   string     `json:"reason,omitempty"`
}

// Label keeps report names for targets that were removed later.
type Label struct {
	Owner    string `json:"owner"`
	Name     string `json:"name"`
	Engine   string `json:"engine"`
	Endpoint string `json:"endpoint"`
}

type HostBucket struct {
	Hour      int64   `json:"h"`
	Samples   int     `json:"n"`
	CPU       float64 `json:"cpu"`
	CPUN      int     `json:"cpun"`
	Steal     float64 `json:"steal"`
	SoftIRQ   float64 `json:"si"`
	Conntrack float64 `json:"ct"`
	Drops     uint64  `json:"drop"`
}

type state struct {
	Settings   Settings                `json:"settings"`
	Revision   uint64                  `json:"revision"`
	Targets    map[string]*TargetState `json:"targets"`
	Buckets    map[string][]Bucket     `json:"buckets"`
	Labels     map[string]Label        `json:"labels"`
	Outages    []Outage                `json:"outages"`
	NextOutage int64                   `json:"next_outage"`
	Host       []HostBucket            `json:"host"`
}

// Monitor is safe for concurrent use. Path "" keeps everything in memory.
type Monitor struct {
	mu    sync.Mutex
	path  string
	data  state
	host  *HostSnapshot
	dirty bool
	saved time.Time
}

func New() *Monitor {
	m := &Monitor{}
	m.data.Settings = Defaults()
	m.init()
	return m
}

// Open loads a history file or starts empty when it does not exist.
func Open(path string) (*Monitor, error) {
	m := New()
	m.path = path
	if info, e := os.Lstat(path); e == nil && !info.Mode().IsRegular() {
		return nil, errors.New("health history must be a regular file")
	}
	f, e := os.Open(path)
	if os.IsNotExist(e) {
		return m, nil
	}
	if e != nil {
		return nil, e
	}
	data, e := io.ReadAll(io.LimitReader(f, maxFileBytes+1))
	_ = f.Close()
	if e != nil {
		return nil, e
	}
	if len(data) > maxFileBytes {
		return nil, errors.New("health history exceeds size limit")
	}
	if e = json.Unmarshal(data, &m.data); e != nil {
		return nil, e
	}
	if e = m.data.Settings.Validate(); e != nil {
		return nil, e
	}
	m.init()
	return m, nil
}

func (m *Monitor) init() {
	if m.data.Targets == nil {
		m.data.Targets = map[string]*TargetState{}
	}
	if m.data.Buckets == nil {
		m.data.Buckets = map[string][]Bucket{}
	}
	if m.data.Labels == nil {
		m.data.Labels = map[string]Label{}
	}
	if m.data.Outages == nil {
		m.data.Outages = []Outage{}
	}
}

func (m *Monitor) Settings() Settings {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.data.Settings
}

// Configure replaces settings when revision matches the one the caller read.
func (m *Monitor) Configure(now time.Time, s Settings, revision uint64) error {
	if e := s.Validate(); e != nil {
		return e
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if revision != m.data.Revision {
		return errors.New("health settings changed; refresh and try again")
	}
	if m.data.Settings.Enabled && !s.Enabled {
		// Paused monitoring cannot see recovery; close outages honestly.
		for key, t := range m.data.Targets {
			m.closeOutage(key, now, "monitoring turned off")
			t.Status, t.Since, t.Fails, t.Successes, t.FailStart = StatusUnknown, now, 0, 0, time.Time{}
		}
		m.host = nil
	}
	m.data.Settings = s
	m.data.Revision++
	m.trim(now)
	return m.saveLocked(now)
}

// Record applies one probe round. Targets missing from the list are retired;
// a target without a result keeps its previous state. It reports whether any
// status changed, so the caller can persist transitions immediately.
func (m *Monitor) Record(now time.Time, targets []Target, results map[string]Result, host *HostSnapshot) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	present := make(map[string]bool, len(targets))
	changed := false
	for _, t := range targets {
		if len(present) >= MaxTargets {
			break
		}
		present[t.Key] = true
		st := m.data.Targets[t.Key]
		if st == nil {
			st = &TargetState{Status: StatusUnknown, Since: now, Recent: []Point{}}
			m.data.Targets[t.Key] = st
		}
		st.Target = t
		m.data.Labels[t.Key] = Label{Owner: t.Owner, Name: t.Name, Engine: t.Engine, Endpoint: t.Endpoint()}
		if r, ok := results[t.Key]; ok && m.apply(st, r, now) {
			changed = true
		}
	}
	for key := range m.data.Targets {
		if !present[key] {
			m.closeOutage(key, now, "removed from configuration")
			delete(m.data.Targets, key)
			changed = true
		}
	}
	if host != nil {
		m.host = host
		m.addHost(now, host)
	}
	m.trim(now)
	m.dirty = true
	return changed
}

func (m *Monitor) apply(st *TargetState, r Result, now time.Time) bool {
	s := m.data.Settings
	fail, recover := s.FailThreshold, s.RecoverThreshold
	if st.Kind == KindService {
		// systemd state is authoritative; there is no packet loss to smooth.
		fail, recover = 1, 1
	}
	previous := -1.0
	if n := len(st.Recent); n > 0 && st.Recent[n-1].R >= 0 {
		previous = st.Recent[n-1].R
	}
	st.Checked = now
	if r.OK {
		st.Successes++
		st.Fails = 0
		st.FailStart = time.Time{}
		rtt := round1(r.RTT)
		st.RTT, st.Error = &rtt, ""
	} else {
		st.Fails++
		st.Successes = 0
		if st.FailStart.IsZero() {
			st.FailStart = now
		}
		st.RTT, st.Error = nil, r.Error
	}
	next := st.Status
	switch {
	case !r.OK && st.Fails >= fail:
		next = StatusDown
	case !r.OK:
		// Keep the current status until the failure threshold is reached.
	case st.Status == StatusDown && st.Successes < recover:
		next = StatusDown
	case s.LatencyWarn > 0 && st.Kind != KindService && r.RTT > float64(s.LatencyWarn):
		next = StatusDegraded
	default:
		next = StatusUp
	}
	changed := next != st.Status
	if changed {
		if next == StatusDown {
			m.openOutage(st, st.FailStart, r.Error)
			st.Since = st.FailStart
		} else {
			if st.Status == StatusDown {
				m.closeOutage(st.Key, now, "")
			}
			st.Since = now
		}
		st.Status = next
	}
	point := Point{T: now.Unix(), R: -1}
	if r.OK {
		point.R = round1(r.RTT)
	}
	st.Recent = append(st.Recent, point)
	if len(st.Recent) > recentPoints {
		st.Recent = append([]Point(nil), st.Recent[len(st.Recent)-recentPoints:]...)
	}
	b := m.bucket(st.Key, now)
	b.Checks++
	if st.Status != StatusDown {
		b.Up++
	}
	if r.OK && st.Kind != KindService {
		b.OK++
		b.Sum += r.RTT
		b.Max = math.Max(b.Max, r.RTT)
		if previous >= 0 {
			b.Jitter += math.Abs(r.RTT - previous)
			b.Pairs++
		}
	} else if r.OK {
		b.OK++
	}
	return changed
}

func (m *Monitor) bucket(key string, now time.Time) *Bucket {
	hour := now.Unix() / 3600 * 3600
	list := m.data.Buckets[key]
	if n := len(list); n == 0 || list[n-1].Hour != hour {
		list = append(list, Bucket{Hour: hour})
		m.data.Buckets[key] = list
	}
	return &m.data.Buckets[key][len(m.data.Buckets[key])-1]
}

func (m *Monitor) addHost(now time.Time, h *HostSnapshot) {
	hour := now.Unix() / 3600 * 3600
	if n := len(m.data.Host); n == 0 || m.data.Host[n-1].Hour != hour {
		m.data.Host = append(m.data.Host, HostBucket{Hour: hour})
	}
	b := &m.data.Host[len(m.data.Host)-1]
	b.Samples++
	if h.CPU != nil {
		b.CPU += *h.CPU
		b.Steal += value(h.Steal)
		b.SoftIRQ += value(h.SoftIRQ)
		b.CPUN++
	}
	if h.ConntrackPercent != nil {
		b.Conntrack = math.Max(b.Conntrack, *h.ConntrackPercent)
	}
	b.Drops += h.Drops + h.EarlyDrops + h.InsertFailed
}

func (m *Monitor) openOutage(st *TargetState, start time.Time, reason string) {
	for i := range m.data.Outages {
		if m.data.Outages[i].Key == st.Key && m.data.Outages[i].End == nil {
			return
		}
	}
	m.data.NextOutage++
	m.data.Outages = append(m.data.Outages, Outage{ID: m.data.NextOutage, Key: st.Key, Owner: st.Owner, Name: st.Name, Engine: st.Engine, Endpoint: st.Endpoint(), Start: start, Reason: reason})
}

func (m *Monitor) closeOutage(key string, now time.Time, note string) {
	for i := range m.data.Outages {
		o := &m.data.Outages[i]
		if o.Key == key && o.End == nil {
			end := now
			o.End = &end
			if note != "" {
				o.Reason = note
			}
		}
	}
}

func (m *Monitor) trim(now time.Time) {
	cutoff := now.Add(-time.Duration(m.data.Settings.RetentionDays) * 24 * time.Hour)
	hour := cutoff.Unix() / 3600 * 3600
	for key, list := range m.data.Buckets {
		i := sort.Search(len(list), func(i int) bool { return list[i].Hour >= hour })
		if i == len(list) {
			delete(m.data.Buckets, key)
			if m.data.Targets[key] == nil {
				delete(m.data.Labels, key)
			}
			continue
		}
		if i > 0 {
			m.data.Buckets[key] = append([]Bucket(nil), list[i:]...)
		}
	}
	i := sort.Search(len(m.data.Host), func(i int) bool { return m.data.Host[i].Hour >= hour })
	m.data.Host = append([]HostBucket(nil), m.data.Host[i:]...)
	kept := m.data.Outages[:0]
	for _, o := range m.data.Outages {
		if o.End == nil || o.End.After(cutoff) {
			kept = append(kept, o)
		}
	}
	m.data.Outages = kept
	if extra := len(m.data.Outages) - maxOutages; extra > 0 {
		m.data.Outages = append([]Outage(nil), m.data.Outages[extra:]...)
	}
}

// Flush writes pending changes when they are older than the save interval or
// when force is set (status transitions, shutdown).
func (m *Monitor) Flush(now time.Time, force bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.dirty || (!force && now.Sub(m.saved) < saveEvery) {
		return nil
	}
	return m.saveLocked(now)
}

func (m *Monitor) saveLocked(now time.Time) error {
	m.dirty = false
	m.saved = now
	if m.path == "" {
		return nil
	}
	if e := os.MkdirAll(filepath.Dir(m.path), 0700); e != nil {
		return e
	}
	return config.Save(m.path, m.data, 0600)
}

func round1(v float64) float64 { return math.Round(v*10) / 10 }
func value(p *float64) float64 {
	if p == nil {
		return 0
	}
	return *p
}
func ratio(up, total int) *float64 {
	if total == 0 {
		return nil
	}
	v := math.Round(10000*float64(up)/float64(total)) / 100
	return &v
}
