package health

import (
	"testing"
	"time"
)

func TestLatencyHistoryFromChecksAndRollups(t *testing.T) {
	m := New()
	ping := Target{Key: "gre-1|icmp", Owner: "gre-1", Name: "Tunnel", Engine: "gre", Kind: KindICMP, Address: "10.0.0.2"}
	unit := Target{Key: "gre-1|svc", Owner: "gre-1", Name: "Tunnel", Engine: "gre", Kind: KindService, Unit: "gre.service"}
	start := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	rtts := []float64{20, 30, -1, 40}
	for i, rtt := range rtts {
		r := Result{OK: rtt >= 0, RTT: rtt}
		if rtt < 0 {
			r.Error = "timeout"
		}
		m.Record(start.Add(time.Duration(i)*10*time.Minute), []Target{ping, unit}, map[string]Result{ping.Key: r, unit.Key: {OK: true}}, nil)
	}
	now := start.Add(35 * time.Minute)

	day, e := m.Latency("gre-1", "24h", now)
	if e != nil {
		t.Fatal(e)
	}
	if len(day.Points) != 24 || day.Step != 3600 || day.Name != "Tunnel" {
		t.Fatalf("24h shape: %d points, step %d", len(day.Points), day.Step)
	}
	hour := day.Points[23]
	if !hour.Time.Equal(start) || hour.Checks != 4 || *hour.Mean != 30 || *hour.Max != 40 || *hour.Loss != 25 {
		t.Fatalf("hour bucket: %+v", hour)
	}
	// Jitter pairs only consecutive answered checks: |30-20| = 10.
	if hour.Jitter == nil || *hour.Jitter != 10 {
		t.Fatalf("jitter: %+v", hour.Jitter)
	}
	if day.Points[0].Mean != nil || day.Points[0].Loss != nil {
		t.Fatalf("empty hours stay empty: %+v", day.Points[0])
	}
	if day.Summary.Checks != 4 {
		t.Fatalf("summary: %+v", day.Summary)
	}

	recent, e := m.Latency("gre-1", "1h", now)
	if e != nil {
		t.Fatal(e)
	}
	if len(recent.Points) != 60 || recent.Summary.Checks != 4 || *recent.Summary.Mean != 30 || *recent.Summary.Loss != 25 {
		t.Fatalf("1h summary: %+v", recent.Summary)
	}
	month, _ := m.Latency("gre-1", "30d", now)
	week, _ := m.Latency("gre-1", "7d", now)
	if len(month.Points) != 30 || len(week.Points) != 28 || month.Summary.Checks != 4 || week.Summary.Checks != 4 {
		t.Fatalf("long ranges: %d/%d points", len(month.Points), len(week.Points))
	}

	if _, e := m.Latency("gre-1", "2y", now); e == nil {
		t.Fatal("unknown range accepted")
	}
	m.Record(now, []Target{unit}, map[string]Result{unit.Key: {OK: true}}, nil)
	if _, e := m.Latency("gre-1", "24h", now); e == nil {
		t.Fatal("service-only owner has no latency")
	}
}
