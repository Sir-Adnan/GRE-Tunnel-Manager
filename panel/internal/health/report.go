package health

import (
	"math"
	"sort"
	"time"
)

type ReportRow struct {
	Owner      string   `json:"owner"`
	Name       string   `json:"name"`
	Engine     string   `json:"engine"`
	Checks     int      `json:"checks"`
	Uptime     *float64 `json:"uptime"`
	Outages    int      `json:"outages"`
	Downtime   float64  `json:"downtime_seconds"`
	Latency    *float64 `json:"latency_ms,omitempty"`
	LatencyMax *float64 `json:"latency_max_ms,omitempty"`
	Jitter     *float64 `json:"jitter_ms,omitempty"`
	Removed    bool     `json:"removed,omitempty"`
}

type HostReport struct {
	CPU           *float64 `json:"cpu_percent,omitempty"`
	Steal         *float64 `json:"steal_percent,omitempty"`
	SoftIRQ       *float64 `json:"softirq_percent,omitempty"`
	ConntrackPeak *float64 `json:"conntrack_peak_percent,omitempty"`
	Drops         uint64   `json:"drops"`
}

// Report summarizes one calendar week. Callers may add maintenance and
// traffic sections, which this package does not own.
type Report struct {
	Start     time.Time   `json:"start"`
	End       time.Time   `json:"end"`
	Offset    int         `json:"offset"`
	Weeks     int         `json:"weeks"`
	Complete  bool        `json:"complete"`
	Generated time.Time   `json:"generated"`
	Rows      []ReportRow `json:"rows"`
	Uptime    *float64    `json:"uptime"`
	Outages   int         `json:"outages"`
	Downtime  float64     `json:"downtime_seconds"`
	Longest   *Outage     `json:"longest,omitempty"`
	Host      HostReport  `json:"host"`
}

// WeekStart returns the local midnight that starts the week containing now,
// moved back offset weeks.
func WeekStart(now time.Time, loc *time.Location, first time.Weekday, offset int) time.Time {
	local := now.In(loc)
	back := (int(local.Weekday()) - int(first) + 7) % 7
	day := time.Date(local.Year(), local.Month(), local.Day(), 0, 0, 0, 0, loc)
	return day.AddDate(0, 0, -back-7*offset)
}

// Report builds the week offset weeks before the current one (0 = this week).
// Hour buckets are UTC hours, so a week boundary in a half-hour time zone is
// accurate to 30 minutes.
func (m *Monitor) Report(now time.Time, loc *time.Location, first time.Weekday, offset int) Report {
	m.mu.Lock()
	defer m.mu.Unlock()
	if loc == nil {
		loc = time.UTC
	}
	weeks := max(1, (m.data.Settings.RetentionDays+6)/7)
	offset = max(0, min(offset, weeks))
	start := WeekStart(now, loc, first, offset)
	end := start.AddDate(0, 0, 7)
	r := Report{Start: start, End: end, Offset: offset, Weeks: weeks + 1, Complete: !end.After(now), Generated: now, Rows: []ReportRow{}}
	a, b := start.Unix(), end.Unix()
	limit := end
	if limit.After(now) {
		limit = now
	}
	rows := map[string]*ReportRow{}
	keysOf := map[string][]string{}
	counts := map[string]rowCount{}
	for key, list := range m.data.Buckets {
		label, ok := m.data.Labels[key]
		if !ok {
			continue
		}
		row := rows[label.Owner]
		if row == nil {
			row = &ReportRow{Owner: label.Owner, Name: label.Name, Engine: label.Engine, Removed: true}
			rows[label.Owner] = row
		}
		if m.data.Targets[key] != nil {
			row.Removed = false
			row.Name = label.Name
		}
		up, okChecks := 0, 0
		sum, jitter, pairs, peak := 0.0, 0.0, 0, 0.0
		for _, x := range list {
			if x.Hour < a || x.Hour >= b {
				continue
			}
			row.Checks += x.Checks
			up += x.Up
			okChecks += x.OK
			sum += x.Sum
			jitter += x.Jitter
			pairs += x.Pairs
			peak = math.Max(peak, x.Max)
		}
		keysOf[label.Owner] = append(keysOf[label.Owner], key)
		// Accumulate in place; ratios are finished below.
		row.Uptime = addPtr(row.Uptime, float64(up))
		row.Latency = addPtr(row.Latency, sum)
		row.LatencyMax = maxPtr(row.LatencyMax, peak, okChecks > 0)
		row.Jitter = addPtr(row.Jitter, jitter)
		c := counts[label.Owner]
		counts[label.Owner] = rowCount{ok: c.ok + okChecks, pairs: c.pairs + pairs}
	}
	totalUp, totalChecks := 0.0, 0
	for owner, row := range rows {
		c := counts[owner]
		if row.Checks == 0 {
			continue
		}
		up := value(row.Uptime)
		totalUp += up
		totalChecks += row.Checks
		row.Uptime = ratio(int(up), row.Checks)
		row.Latency = mean(value(row.Latency), c.ok)
		if c.ok == 0 {
			row.LatencyMax = nil
		}
		row.Jitter = mean(value(row.Jitter), c.pairs)
		row.Outages, row.Downtime = m.downtime(keysOf[owner], start, limit)
		r.Outages += row.Outages
		r.Downtime += row.Downtime
		r.Rows = append(r.Rows, *row)
	}
	sort.Slice(r.Rows, func(i, j int) bool {
		if r.Rows[i].Removed != r.Rows[j].Removed {
			return !r.Rows[i].Removed
		}
		return r.Rows[i].Owner < r.Rows[j].Owner
	})
	r.Uptime = ratio(int(totalUp), totalChecks)
	for i := range m.data.Outages {
		o := m.data.Outages[i]
		if d := overlap(o, start, limit); d > 0 && (r.Longest == nil || d > overlap(*r.Longest, start, limit)) {
			longest := o
			r.Longest = &longest
		}
	}
	cpu, steal, softirq, n, peak := 0.0, 0.0, 0.0, 0, -1.0
	for _, h := range m.data.Host {
		if h.Hour < a || h.Hour >= b {
			continue
		}
		cpu += h.CPU
		steal += h.Steal
		softirq += h.SoftIRQ
		n += h.CPUN
		peak = math.Max(peak, h.Conntrack)
		r.Host.Drops += h.Drops
	}
	r.Host.CPU, r.Host.Steal, r.Host.SoftIRQ = mean(cpu, n), mean(steal, n), mean(softirq, n)
	if peak >= 0 {
		p := round1(peak)
		r.Host.ConntrackPeak = &p
	}
	return r
}

type rowCount struct{ ok, pairs int }

// downtime merges the outage intervals of an owner's targets so that two
// destinations failing together are not counted twice.
func (m *Monitor) downtime(keys []string, from, to time.Time) (int, float64) {
	wanted := map[string]bool{}
	for _, k := range keys {
		wanted[k] = true
	}
	type span struct{ a, b time.Time }
	spans := []span{}
	count := 0
	for _, o := range m.data.Outages {
		if !wanted[o.Key] {
			continue
		}
		end := to
		if o.End != nil && o.End.Before(to) {
			end = *o.End
		}
		a := o.Start
		if a.Before(from) {
			a = from
		}
		if end.After(a) {
			spans = append(spans, span{a, end})
			if !o.Start.Before(from) {
				count++
			}
		}
	}
	sort.Slice(spans, func(i, j int) bool { return spans[i].a.Before(spans[j].a) })
	total := 0.0
	var cur *span
	for i := range spans {
		s := spans[i]
		if cur == nil || s.a.After(cur.b) {
			if cur != nil {
				total += cur.b.Sub(cur.a).Seconds()
			}
			c := s
			cur = &c
			continue
		}
		if s.b.After(cur.b) {
			cur.b = s.b
		}
	}
	if cur != nil {
		total += cur.b.Sub(cur.a).Seconds()
	}
	return count, math.Round(total)
}

func overlap(o Outage, from, to time.Time) time.Duration {
	end := to
	if o.End != nil && o.End.Before(to) {
		end = *o.End
	}
	a := o.Start
	if a.Before(from) {
		a = from
	}
	if end.After(a) {
		return end.Sub(a)
	}
	return 0
}

func addPtr(p *float64, v float64) *float64 {
	x := value(p) + v
	return &x
}
func maxPtr(p *float64, v float64, valid bool) *float64 {
	if !valid {
		return p
	}
	x := math.Max(value(p), round1(v))
	return &x
}
func mean(sum float64, n int) *float64 {
	if n == 0 {
		return nil
	}
	v := round1(sum / float64(n))
	return &v
}
