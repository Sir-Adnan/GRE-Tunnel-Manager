package health

import (
	"math"
	"sort"
	"time"
)

type TargetView struct {
	TargetState
	Uptime24h *float64 `json:"uptime_24h"`
}

// OwnerView groups the probes of one connection or resource.
type OwnerView struct {
	Owner     string       `json:"owner"`
	Name      string       `json:"name"`
	Engine    string       `json:"engine"`
	Status    string       `json:"status"`
	Since     time.Time    `json:"since"`
	Latency   *float64     `json:"latency_ms,omitempty"`
	Uptime24h *float64     `json:"uptime_24h"`
	Uptime7d  *float64     `json:"uptime_7d"`
	Uptime30d *float64     `json:"uptime_30d"`
	Hours     []*float64   `json:"hours"`
	Days      []*float64   `json:"days"`
	Targets   []TargetView `json:"targets"`
}

type Summary struct {
	Owners      int      `json:"owners"`
	Up          int      `json:"up"`
	Degraded    int      `json:"degraded"`
	Down        int      `json:"down"`
	Unknown     int      `json:"unknown"`
	OpenOutages int      `json:"open_outages"`
	Uptime24h   *float64 `json:"uptime_24h"`
	Uptime7d    *float64 `json:"uptime_7d"`
	Latency     *float64 `json:"latency_ms,omitempty"`
}

type View struct {
	Settings Settings      `json:"settings"`
	Revision uint64        `json:"revision"`
	Time     time.Time     `json:"time"`
	Summary  Summary       `json:"summary"`
	Owners   []OwnerView   `json:"owners"`
	Outages  []Outage      `json:"outages"`
	Host     *HostSnapshot `json:"host,omitempty"`
}

// sums adds buckets of keys in [from, to).
func (m *Monitor) sums(keys []string, from, to time.Time) (up, total int) {
	a, b := from.Unix(), to.Unix()
	for _, key := range keys {
		for _, x := range m.data.Buckets[key] {
			if x.Hour >= a && x.Hour < b {
				up += x.Up
				total += x.Checks
			}
		}
	}
	return
}

// ownerStatus combines destinations: all down is down, some down is degraded.
func ownerStatus(targets []TargetView) (string, time.Time) {
	counts := map[string]int{}
	var since time.Time
	for _, t := range targets {
		counts[t.Status]++
		if since.IsZero() || t.Since.After(since) {
			since = t.Since
		}
	}
	n := len(targets)
	switch {
	case n == 0 || counts[StatusUnknown] == n:
		return StatusUnknown, since
	case counts[StatusDown] == n:
		return StatusDown, since
	case counts[StatusDown] > 0 || counts[StatusDegraded] > 0:
		return StatusDegraded, since
	case counts[StatusUnknown] > 0:
		return StatusUnknown, since
	}
	return StatusUp, since
}

// View reports current status, uptime windows and recent outages. Day cells
// follow loc's calendar; hour cells are the last 24 clock hours.
func (m *Monitor) View(now time.Time, loc *time.Location) View {
	m.mu.Lock()
	defer m.mu.Unlock()
	if loc == nil {
		loc = time.UTC
	}
	v := View{Settings: m.data.Settings, Revision: m.data.Revision, Time: now, Owners: []OwnerView{}, Outages: []Outage{}, Host: m.host}
	byOwner := map[string]*OwnerView{}
	keys := map[string][]string{}
	order := []string{}
	for key, st := range m.data.Targets {
		o := byOwner[st.Owner]
		if o == nil {
			o = &OwnerView{Owner: st.Owner, Name: st.Name, Engine: st.Engine, Targets: []TargetView{}}
			byOwner[st.Owner] = o
			order = append(order, st.Owner)
		}
		up, total := m.sums([]string{key}, now.Add(-24*time.Hour), now.Add(time.Hour))
		t := TargetView{TargetState: *st, Uptime24h: ratio(up, total)}
		t.Recent = append([]Point(nil), st.Recent...)
		o.Targets = append(o.Targets, t)
		keys[st.Owner] = append(keys[st.Owner], key)
	}
	sort.Strings(order)
	allKeys := []string{}
	latencies := []float64{}
	end := now.Add(time.Hour)
	for _, id := range order {
		o := byOwner[id]
		sort.Slice(o.Targets, func(i, j int) bool { return o.Targets[i].Key < o.Targets[j].Key })
		o.Status, o.Since = ownerStatus(o.Targets)
		k := keys[id]
		allKeys = append(allKeys, k...)
		o.Uptime24h = ratio(m.sums(k, now.Add(-24*time.Hour), end))
		o.Uptime7d = ratio(m.sums(k, now.Add(-7*24*time.Hour), end))
		o.Uptime30d = ratio(m.sums(k, now.Add(-30*24*time.Hour), end))
		sum, n := 0.0, 0
		for _, t := range o.Targets {
			if t.RTT != nil && t.Kind != KindService {
				sum += *t.RTT
				n++
			}
		}
		if n > 0 {
			avg := round1(sum / float64(n))
			o.Latency = &avg
			latencies = append(latencies, avg)
		}
		hourStart := time.Unix(now.Unix()/3600*3600, 0)
		for i := 23; i >= 0; i-- {
			from := hourStart.Add(-time.Duration(i) * time.Hour)
			o.Hours = append(o.Hours, ratio(m.sums(k, from, from.Add(time.Hour))))
		}
		days := min(m.data.Settings.RetentionDays, 30)
		local := now.In(loc)
		today := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
		for i := days - 1; i >= 0; i-- {
			from := today.AddDate(0, 0, -i)
			o.Days = append(o.Days, ratio(m.sums(k, from, from.AddDate(0, 0, 1))))
		}
		switch o.Status {
		case StatusUp:
			v.Summary.Up++
		case StatusDegraded:
			v.Summary.Degraded++
		case StatusDown:
			v.Summary.Down++
		default:
			v.Summary.Unknown++
		}
		v.Owners = append(v.Owners, *o)
	}
	v.Summary.Owners = len(v.Owners)
	v.Summary.Uptime24h = ratio(m.sums(allKeys, now.Add(-24*time.Hour), end))
	v.Summary.Uptime7d = ratio(m.sums(allKeys, now.Add(-7*24*time.Hour), end))
	if len(latencies) > 0 {
		sum := 0.0
		for _, l := range latencies {
			sum += l
		}
		avg := round1(sum / float64(len(latencies)))
		v.Summary.Latency = &avg
	}
	for i := len(m.data.Outages) - 1; i >= 0; i-- {
		o := m.data.Outages[i]
		if o.End == nil {
			v.Summary.OpenOutages++
		}
		if len(v.Outages) < 200 {
			v.Outages = append(v.Outages, o)
		}
	}
	return v
}

// OwnerHealth is the slice of state maintenance conditions read.
type OwnerHealth struct {
	Known   bool
	Down    bool
	Latency float64
}

// Owner reports whether any probe of owner is down and its mean current RTT.
func (m *Monitor) Owner(owner string) OwnerHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	h := OwnerHealth{}
	sum, n := 0.0, 0
	for _, st := range m.data.Targets {
		if st.Owner != owner || st.Status == StatusUnknown {
			continue
		}
		h.Known = true
		if st.Status == StatusDown {
			h.Down = true
		}
		if st.RTT != nil && st.Kind != KindService {
			sum += *st.RTT
			n++
		}
	}
	if n > 0 {
		h.Latency = sum / float64(n)
	} else {
		h.Latency = math.NaN()
	}
	return h
}
