package health

import (
	"errors"
	"math"
	"time"
)

// Latency history of one owner, read from data the monitor already keeps:
// the last hour from each target's recent checks, longer ranges from the
// hourly rollups. Nothing extra is probed or stored. Service targets have no
// round-trip time and are left out.

// LatencyRanges lists the ranges a chart may ask for, with their step.
var LatencyRanges = map[string]struct{ Span, Step time.Duration }{
	"1h":  {time.Hour, time.Minute},
	"24h": {24 * time.Hour, time.Hour},
	"7d":  {7 * 24 * time.Hour, 6 * time.Hour},
	"30d": {30 * 24 * time.Hour, 24 * time.Hour},
}

// LatencyPoint summarizes the checks of one step. Mean, Max and Jitter cover
// answered checks (nil when none answered); Loss is the percentage of failed
// checks (nil without checks).
type LatencyPoint struct {
	Time   time.Time `json:"t"`
	Checks int       `json:"checks"`
	Mean   *float64  `json:"mean_ms"`
	Max    *float64  `json:"max_ms"`
	Jitter *float64  `json:"jitter_ms"`
	Loss   *float64  `json:"loss"`
}

// LatencyHistory is the chart data of one owner; Summary covers the range.
type LatencyHistory struct {
	Owner   string         `json:"owner"`
	Name    string         `json:"name"`
	Range   string         `json:"range"`
	Step    int64          `json:"step_seconds"`
	Points  []LatencyPoint `json:"points"`
	Summary LatencyPoint   `json:"summary"`
}

// latencySum accumulates checks; it maps onto Bucket fields.
type latencySum struct {
	checks, ok, pairs int
	sum, max, jitter  float64
}

func (s *latencySum) add(b Bucket) {
	s.checks += b.Checks
	s.ok += b.OK
	s.sum += b.Sum
	s.max = math.Max(s.max, b.Max)
	s.jitter += b.Jitter
	s.pairs += b.Pairs
}

func (s latencySum) point(at time.Time) LatencyPoint {
	p := LatencyPoint{Time: at, Checks: s.checks, Loss: ratio(s.checks-s.ok, s.checks)}
	if s.ok > 0 {
		mean, peak := round1(s.sum/float64(s.ok)), round1(s.max)
		p.Mean, p.Max = &mean, &peak
	}
	if s.pairs > 0 {
		jitter := round1(s.jitter / float64(s.pairs))
		p.Jitter = &jitter
	}
	return p
}

// Latency returns the latency history of owner over one of LatencyRanges.
func (m *Monitor) Latency(owner, span string, now time.Time) (LatencyHistory, error) {
	r, ok := LatencyRanges[span]
	if !ok {
		return LatencyHistory{}, errors.New("unknown latency range")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	var targets []*TargetState
	for _, st := range m.data.Targets {
		if st.Owner == owner && st.Kind != KindService {
			targets = append(targets, st)
		}
	}
	if len(targets) == 0 {
		return LatencyHistory{}, errors.New("no latency checks for this connection")
	}
	h := LatencyHistory{Owner: owner, Name: targets[0].Name, Range: span, Step: int64(r.Step / time.Second)}
	step := int64(r.Step / time.Second)
	end := now.Unix()/step*step + step
	start := end - int64(r.Span/time.Second)
	steps := make([]latencySum, (end-start)/step)
	var total latencySum
	at := func(t int64) *latencySum {
		if t < start || t >= end {
			return nil
		}
		return &steps[(t-start)/step]
	}
	for _, st := range targets {
		if span == "1h" {
			// Recent checks: R < 0 is a failed check.
			previous := -1.0
			for _, p := range st.Recent {
				s := at(p.T)
				if s == nil {
					previous = p.R
					continue
				}
				b := Bucket{Checks: 1}
				if p.R >= 0 {
					b.OK, b.Sum, b.Max = 1, p.R, p.R
					if previous >= 0 {
						b.Jitter, b.Pairs = math.Abs(p.R-previous), 1
					}
				}
				previous = p.R
				s.add(b)
				total.add(b)
			}
			continue
		}
		for _, b := range m.data.Buckets[st.Key] {
			if s := at(b.Hour); s != nil {
				s.add(b)
				total.add(b)
			}
		}
	}
	h.Points = make([]LatencyPoint, len(steps))
	for i, s := range steps {
		h.Points[i] = s.point(time.Unix(start+int64(i)*step, 0).UTC())
	}
	h.Summary = total.point(time.Unix(start, 0).UTC())
	return h, nil
}
