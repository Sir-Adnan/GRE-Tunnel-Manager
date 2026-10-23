package control

import (
	"context"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"path/filepath"
	"testing"
	"time"
)

func TestTrafficResetCapturesBytesPreservesRawBaselineAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	connections, _, _ := model.ParseState(stateFixture())
	inv := Inventory{Connections: connections}
	r := &fakeRunner{}
	path := filepath.Join(t.TempDir(), "metrics.json")
	m, e := NewMetrics(r, path)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = m.Configure(ctx, MetricsSettings{Enabled: true, Interval: 15, RetentionHours: 24}, inv); e != nil {
		t.Fatal(e)
	}
	r.counter = 100
	if e = m.Tick(ctx, inv); e != nil {
		t.Fatal(e)
	}
	before := m.View()
	r.counter = 130
	reset, e := m.Change(ctx, "metrics-reset", TrafficChange{ID: "F000001", Revision: before.Revision}, inv)
	if e != nil {
		t.Fatal(e)
	}
	c := reset.Counters["F000001"]
	if c.Received != 130 || c.BaselineReceived != 130 || c.LastReceived != 130 || len(reset.Cycles["F000001"]) != 1 || len(reset.History["F000001"]) != 0 {
		t.Fatal(reset)
	}
	if _, e = m.Change(ctx, "metrics-reset", TrafficChange{ID: "F000001", Revision: before.Revision}, inv); e == nil {
		t.Fatal("duplicate reset accepted")
	}
	m, e = NewMetrics(r, path)
	if e != nil {
		t.Fatal(e)
	}
	r.counter = 150
	if e = m.Tick(ctx, inv); e != nil {
		t.Fatal(e)
	}
	c = m.View().Counters["F000001"]
	if c.Received-c.BaselineReceived != 20 {
		t.Fatal("reset rebounded", c)
	}
	if m.View().Settings.RetentionHours != 24 {
		t.Fatal("lost retention")
	}
}
func TestTrafficQuotaIsAdvisoryAndArchivedForgetIsScoped(t *testing.T) {
	ctx := context.Background()
	r := &fakeRunner{}
	m, _ := NewMetrics(r, filepath.Join(t.TempDir(), "metrics.json"))
	inv := Inventory{Connections: []model.Connection{{ID: "F000001"}}}
	p := TrafficPolicy{Label: "Customer 1", Limit: 1024, Direction: "total"}
	v, e := m.Change(ctx, "metrics-policy", TrafficChange{ID: "F000001", Policy: p}, inv)
	if e != nil {
		t.Fatal(e)
	}
	if len(r.calls) != 0 || v.Policies["F000001"].Limit != 1024 {
		t.Fatal("quota changed network", r.calls, v)
	}
	if _, e = m.Change(ctx, "metrics-forget", TrafficChange{ID: "F000001", Revision: v.Revision}, inv); e == nil {
		t.Fatal("forgot active resource")
	}
	// Policies may exist before the first sample; deleted policy-only resources can be forgotten.
	v.Counters["F000001"] = Traffic{Received: 1}
	m.view = v
	v, e = m.Change(ctx, "metrics-forget", TrafficChange{ID: "F000001", Revision: v.Revision}, Inventory{})
	if e != nil || len(v.Counters) != 0 || len(v.Policies) != 0 {
		t.Fatal(e, v)
	}
}
func TestTrafficHistoryBoundsExpiryAndDeepCopies(t *testing.T) {
	m, _ := NewMetrics(&fakeRunner{}, filepath.Join(t.TempDir(), "metrics.json"))
	m.view.Settings.RetentionHours = 24
	start := time.Now().UTC().Add(-4 * time.Hour)
	for i := 0; i < maxTrafficPoints+50; i++ {
		now := start.Add(time.Duration(i) * time.Second)
		m.view.Counters["F000001"] = Traffic{Updated: now, Received: uint64(i)}
		m.recordHistory(now)
	}
	if len(m.view.History["F000001"]) != maxTrafficPoints {
		t.Fatal("unbounded history")
	}
	v := m.View()
	v.History["F000001"][0].Received = 99999
	v.Policies["F000001"] = TrafficPolicy{Label: "changed"}
	if m.view.History["F000001"][0].Received == 99999 || len(m.view.Policies) != 0 {
		t.Fatal("view aliases state")
	}
	m.trimHistory(start.Add(30 * time.Hour))
	if len(m.view.History) != 0 {
		t.Fatal("expired samples retained")
	}
}
func TestTrafficFailedPersistenceRestoresCycleAndRejectsUnsafePolicy(t *testing.T) {
	dir := t.TempDir()
	m, _ := NewMetrics(&fakeRunner{}, filepath.Join(dir, "metrics.json"))
	m.view.Counters["F000001"] = Traffic{Received: 100}
	m.Path = dir // atomic file replacement must fail against a directory
	if _, e := m.Change(context.Background(), "metrics-reset", TrafficChange{ID: "F000001"}, Inventory{}); e == nil {
		t.Fatal("save unexpectedly succeeded")
	}
	if c := m.View().Counters["F000001"]; c.BaselineReceived != 0 || len(m.View().Cycles) != 0 {
		t.Fatal("failed reset altered state", c)
	}
	for _, p := range []TrafficPolicy{{Direction: "shell"}, {Direction: "total", Label: "a\ncommand"}, {Direction: "total", Label: "\u202eright"}, {Direction: "total", Limit: maxTrafficBytes + 1}} {
		if validTrafficPolicy(p) {
			t.Fatal("unsafe policy accepted", p)
		}
	}
	if files, e := filepath.Glob(filepath.Join(dir, ".panel-*")); e != nil || len(files) != 0 {
		t.Fatal("temporary ledger leaked", files, e)
	}
}
func TestTrafficSummaryDoesNotCopyArchivesIntoJobsOrPolling(t *testing.T) {
	m, _ := NewMetrics(&fakeRunner{}, filepath.Join(t.TempDir(), "metrics.json"))
	m.view.Settings.RetentionHours = 24
	m.view.History["F000001"] = []TrafficPoint{{Time: time.Now().UTC(), Received: 42}}
	m.view.Cycles["F000001"] = []TrafficCycle{{End: time.Now().UTC(), Received: 10}}
	v := m.Summary()
	if len(v.History) != 0 || len(v.Cycles) != 0 {
		t.Fatal("polling copied archives")
	}
	a, e := m.Archive("F000001")
	if e != nil || len(a.History) != 1 || len(a.Cycles) != 1 {
		t.Fatal(a, e)
	}
	a.History[0].Received = 1000
	if m.view.History["F000001"][0].Received != 42 {
		t.Fatal("archive aliases state")
	}
	if _, e = m.Archive("../../etc/passwd"); e == nil {
		t.Fatal("path accepted")
	}
	if _, e = m.Configure(context.Background(), MetricsSettings{Interval: 60}, Inventory{}, 99); e == nil {
		t.Fatal("stale settings overwrote ledger")
	}
}
