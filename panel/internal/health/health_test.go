package health

import (
	"context"
	"net"
	"net/netip"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

var epoch = time.Date(2026, 11, 2, 10, 0, 0, 0, time.UTC)

func target(owner, address string) Target {
	return Target{Key: owner + "|tcp|" + address, Owner: owner, Name: "Tunnel " + owner, Engine: "nftables", Kind: KindTCP, Address: address, Port: 443}
}

func enabled() *Monitor {
	m := New()
	s := Defaults()
	s.Enabled = true
	if e := m.Configure(epoch, s, 0); e != nil {
		panic(e)
	}
	return m
}

func round(m *Monitor, at time.Time, targets []Target, ok map[string]bool, rtt float64) {
	results := map[string]Result{}
	for _, t := range targets {
		if ok[t.Key] {
			results[t.Key] = Result{OK: true, RTT: rtt}
		} else {
			results[t.Key] = Result{Error: "timeout"}
		}
	}
	m.Record(at, targets, results, nil)
}

func TestThresholdsOpenAndCloseOneOutage(t *testing.T) {
	m := enabled()
	a := target("F000001", "198.51.100.20")
	targets := []Target{a}
	at := epoch
	step := func(ok bool) {
		round(m, at, targets, map[string]bool{a.Key: ok}, 40)
		at = at.Add(30 * time.Second)
	}
	step(true)
	if got := m.View(at, nil).Owners[0].Status; got != StatusUp {
		t.Fatalf("first success = %s, want up", got)
	}
	failStart := at
	step(false)
	step(false)
	if got := m.View(at, nil).Owners[0].Status; got != StatusUp {
		t.Fatalf("two failures below threshold = %s, want up", got)
	}
	step(false)
	v := m.View(at, nil)
	if v.Owners[0].Status != StatusDown || v.Summary.OpenOutages != 1 || !v.Outages[0].Start.Equal(failStart) {
		t.Fatalf("third failure should open one outage at the first failure: %+v", v.Outages)
	}
	step(true)
	if got := m.View(at, nil).Owners[0].Status; got != StatusDown {
		t.Fatalf("one success below recovery threshold = %s, want down", got)
	}
	step(true)
	v = m.View(at, nil)
	if v.Owners[0].Status != StatusUp || v.Summary.OpenOutages != 0 || v.Outages[0].End == nil {
		t.Fatalf("recovery should close the outage: %+v", v.Outages)
	}
	// Six checks, two counted as down (the third failure and the first success).
	if got := *v.Owners[0].Uptime24h; got != 66.67 {
		t.Fatalf("uptime = %v, want 66.67", got)
	}
}

func TestOwnerStatusCombinesDestinations(t *testing.T) {
	m := enabled()
	a, b := target("F000002", "198.51.100.20"), target("F000002", "198.51.100.30")
	for i := range 3 {
		round(m, epoch.Add(time.Duration(i)*30*time.Second), []Target{a, b}, map[string]bool{a.Key: true}, 20)
	}
	if got := m.View(epoch.Add(2*time.Minute), nil).Owners[0].Status; got != StatusDegraded {
		t.Fatalf("one of two destinations down = %s, want degraded", got)
	}
	if h := m.Owner("F000002"); !h.Known || !h.Down || h.Latency != 20 {
		t.Fatalf("owner health = %+v", h)
	}
}

func TestLatencyWarningMarksDegraded(t *testing.T) {
	m := enabled()
	a := target("F000003", "198.51.100.20")
	round(m, epoch, []Target{a}, map[string]bool{a.Key: true}, 450)
	if got := m.View(epoch, nil).Owners[0].Status; got != StatusDegraded {
		t.Fatalf("slow answer = %s, want degraded", got)
	}
}

func TestServiceTargetsUseSystemdStateImmediately(t *testing.T) {
	m := enabled()
	s := Target{Key: "F000004|service", Owner: "F000004", Kind: KindService, Unit: "gtm-F000004"}
	m.Record(epoch, []Target{s}, map[string]Result{s.Key: {Error: "failed"}}, nil)
	if got := m.View(epoch, nil).Owners[0].Status; got != StatusDown {
		t.Fatalf("failed unit = %s, want down at once", got)
	}
}

func TestRemovedTargetClosesOutageAndKeepsReportLabel(t *testing.T) {
	m := enabled()
	a := target("F000005", "198.51.100.20")
	for i := range 3 {
		round(m, epoch.Add(time.Duration(i)*time.Minute), []Target{a}, nil, 0)
	}
	m.Record(epoch.Add(5*time.Minute), nil, nil, nil)
	v := m.View(epoch.Add(5*time.Minute), nil)
	if len(v.Owners) != 0 || v.Outages[0].End == nil {
		t.Fatalf("removed target should vanish and close its outage: %+v", v)
	}
	r := m.Report(epoch.Add(time.Hour), time.UTC, time.Monday, 0)
	if len(r.Rows) != 1 || !r.Rows[0].Removed || r.Rows[0].Name != "Tunnel F000005" {
		t.Fatalf("report should keep the removed tunnel: %+v", r.Rows)
	}
}

func TestReportMergesOverlappingDestinationOutages(t *testing.T) {
	m := enabled()
	a, b := target("F000006", "198.51.100.20"), target("F000006", "198.51.100.30")
	at := epoch
	for i := range 10 {
		ok := map[string]bool{}
		if i >= 6 {
			ok[a.Key], ok[b.Key] = true, true
		}
		round(m, at, []Target{a, b}, ok, 30)
		at = at.Add(time.Minute)
	}
	r := m.Report(at, time.UTC, time.Monday, 0)
	// Both destinations fail from minute 0 to the second success at minute 7.
	if len(r.Rows) != 1 || r.Rows[0].Outages != 2 || r.Rows[0].Downtime != 420 {
		t.Fatalf("downtime should merge to 7 minutes: %+v", r.Rows)
	}
	if r.Longest == nil || r.Rows[0].Latency == nil || *r.Rows[0].Latency != 30 {
		t.Fatalf("longest outage and latency expected: %+v", r)
	}
}

func TestWeekStartUsesLocalCalendar(t *testing.T) {
	tehran := time.FixedZone("IRST", 3*3600+1800)
	// Wednesday 2026-11-04 01:00 in Tehran is still Tuesday in UTC.
	now := time.Date(2026, 11, 3, 21, 30, 0, 0, time.UTC)
	got := WeekStart(now, tehran, time.Saturday, 0)
	if want := time.Date(2026, 10, 31, 0, 0, 0, 0, tehran); !got.Equal(want) {
		t.Fatalf("week start = %v, want %v", got, want)
	}
	if got := WeekStart(now, tehran, time.Saturday, 1); !got.Equal(time.Date(2026, 10, 24, 0, 0, 0, 0, tehran)) {
		t.Fatalf("previous week = %v", got)
	}
}

func TestRetentionTrimsBucketsAndClosedOutages(t *testing.T) {
	m := enabled()
	a := target("F000007", "198.51.100.20")
	for i := range 4 {
		round(m, epoch.Add(time.Duration(i)*time.Minute), []Target{a}, map[string]bool{a.Key: i == 3}, 10)
	}
	round(m, epoch.Add(4*time.Minute), []Target{a}, map[string]bool{a.Key: true}, 10)
	later := epoch.Add(31 * 24 * time.Hour)
	round(m, later, []Target{a}, map[string]bool{a.Key: true}, 10)
	v := m.View(later, nil)
	if len(v.Outages) != 0 || len(m.data.Buckets[a.Key]) != 1 {
		t.Fatalf("old history should be trimmed: outages=%d buckets=%d", len(v.Outages), len(m.data.Buckets[a.Key]))
	}
}

func TestConfigureChecksRevisionAndPersists(t *testing.T) {
	path := filepath.Join(t.TempDir(), "health.json")
	m, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	s := Defaults()
	s.Enabled, s.Interval = true, 60
	if e = m.Configure(epoch, s, 7); e == nil {
		t.Fatal("stale revision accepted")
	}
	if e = m.Configure(epoch, s, 0); e != nil {
		t.Fatal(e)
	}
	a := target("F000008", "198.51.100.20")
	round(m, epoch, []Target{a}, map[string]bool{a.Key: true}, 12)
	if e = m.Flush(epoch, true); e != nil {
		t.Fatal(e)
	}
	again, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if got := again.Settings(); got.Interval != 60 || !got.Enabled {
		t.Fatalf("settings not restored: %+v", got)
	}
	if v := again.View(epoch, nil); len(v.Owners) != 1 || v.Revision != 1 {
		t.Fatalf("state not restored: %+v", v)
	}
	bad := Defaults()
	bad.Interval = 5
	if e = again.Configure(epoch, bad, 1); e == nil {
		t.Fatal("invalid interval accepted")
	}
}

func TestDisablingClosesOutagesHonestly(t *testing.T) {
	m := enabled()
	a := target("F000009", "198.51.100.20")
	for i := range 3 {
		round(m, epoch.Add(time.Duration(i)*time.Minute), []Target{a}, nil, 0)
	}
	s := m.Settings()
	s.Enabled = false
	if e := m.Configure(epoch.Add(time.Hour), s, 1); e != nil {
		t.Fatal(e)
	}
	v := m.View(epoch.Add(time.Hour), nil)
	if v.Summary.OpenOutages != 0 || v.Outages[0].Reason != "monitoring turned off" || v.Owners[0].Status != StatusUnknown {
		t.Fatalf("pause should close outages and reset status: %+v", v)
	}
}

func TestHostSamplerDeltasAndHints(t *testing.T) {
	files := map[string]string{
		"/proc/sys/net/netfilter/nf_conntrack_count":                   "90000\n",
		"/proc/sys/net/netfilter/nf_conntrack_max":                     "100000\n",
		"/sys/module/nf_conntrack/parameters/hashsize":                 "8192\n",
		"/proc/sys/net/netfilter/nf_conntrack_tcp_timeout_established": "432000\n",
		"/proc/net/stat/nf_conntrack":                                  "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop\n0000 0 0 0 0 0 0 0 0 00000001 0000000a 00000000\n0000 0 0 0 0 0 0 0 0 00000000 00000005 00000000\n",
		"/proc/stat":                                                   "cpu 100 0 100 700 0 0 50 50 0 0\n",
	}
	h := &HostSampler{read: func(p string) ([]byte, error) {
		if v, ok := files[p]; ok {
			return []byte(v), nil
		}
		return nil, net.ErrClosed
	}}
	first := h.Sample(epoch)
	if first.CPU != nil || first.Drops != 0 || *first.ConntrackPercent != 90 {
		t.Fatalf("first sample is a baseline: %+v", first)
	}
	files["/proc/net/stat/nf_conntrack"] = "entries searched found new invalid ignore delete delete_list insert insert_failed drop early_drop\n0000 0 0 0 0 0 0 0 0 00000001 00000014 00000000\n0000 0 0 0 0 0 0 0 0 00000000 00000005 00000000\n"
	files["/proc/stat"] = "cpu 200 0 150 750 0 0 100 100 0 0\n"
	s := h.Sample(epoch.Add(30 * time.Second))
	if s.Drops != 10 || s.InsertFailed != 0 {
		t.Fatalf("drop delta = %d", s.Drops)
	}
	// Delta 300 ticks: idle 50, steal 50, softirq 50.
	if *s.CPU != 83.3 || *s.Steal != 16.7 || *s.SoftIRQ != 16.7 {
		t.Fatalf("cpu shares = %v %v %v", *s.CPU, *s.Steal, *s.SoftIRQ)
	}
	want := map[string]bool{HintConntrackTimeout: true, HintConntrackHigh: true, HintConntrackDrops: true, HintConntrackBuckets: true, HintSteal: true}
	if len(s.Hints) != len(want) {
		t.Fatalf("hints = %v", s.Hints)
	}
	for _, hint := range s.Hints {
		if !want[hint] {
			t.Fatalf("unexpected hint %s", hint)
		}
	}
}

func TestTCPProbeSucceedsAndReportsRefusal(t *testing.T) {
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		t.Skip(e)
	}
	go func() {
		for {
			c, e := listener.Accept()
			if e != nil {
				return
			}
			c.Close()
		}
	}()
	port := listener.Addr().(*net.TCPAddr).Port
	ok := target("F000010", "127.0.0.1")
	ok.Port = port
	if r := (NetProber{Timeout: time.Second}).Probe(context.Background(), ok); !r.OK {
		t.Fatalf("open port probe failed: %+v", r)
	}
	listener.Close()
	closed := ok
	closed.Key = "closed"
	results := Run(context.Background(), NetProber{Timeout: time.Second}, []Target{closed, {Key: "svc", Kind: KindService}}, 4)
	if r := results["closed"]; r.OK || (r.Error != "refused" && r.Error != "timeout") {
		t.Fatalf("closed port probe = %+v", r)
	}
	if _, present := results["svc"]; present {
		t.Fatal("service targets are not probed over the network")
	}
}

func TestICMPChecksum(t *testing.T) {
	// RFC 1071 example words.
	if got := checksum([]byte{0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7}); got != 0x220d {
		t.Fatalf("checksum = %#x", got)
	}
	if _, e := netip.ParseAddr("not-an-ip"); e == nil {
		t.Fatal("parser accepted garbage")
	}
	if got := (Target{Kind: KindTCP, Address: "2001:db8::1", Port: 443}).Endpoint(); got != "[2001:db8::1]:443" {
		t.Fatalf("endpoint = %s", got)
	}
	_ = strconv.Itoa
}
