package control

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/maintenance"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// scriptRunner answers Bash API calls from a map and records them.
type scriptRunner struct {
	mu      sync.Mutex
	answers map[string]string
	calls   []string
}

func (s *scriptRunner) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if name != "/bin/bash" || len(args) < 3 {
		return "", nil
	}
	s.calls = append(s.calls, strings.Join(args[2:], " "))
	return s.answers[args[2]], nil
}

func row(id, name, target string, enabled bool) string {
	c := model.Connection{ID: id, Name: name, Engine: "nftables", Protocol: "tcp", Bind: "0.0.0.0", Ports: "443", Strategy: "single", Enabled: enabled, SNAT: "masquerade", Interface: "any", Targets: []model.Target{{IP: target, Port: 443, Weight: 1}}, Options: map[string]string{}}
	rows, e := c.Rows(id)
	if e != nil {
		panic(e)
	}
	return rows[0]
}

func TestHistoryPairsPointsWithLaterStateAndReviewsRestore(t *testing.T) {
	a, b := row("F000001", "A", "192.0.2.1", true), row("F000002", "B", "192.0.2.2", true)
	b2 := row("F000002", "B", "192.0.2.9", false)
	revision := strings.Repeat("a", 64)
	out := "revision\t" + revision + "\ntotal\t3\n" +
		"point\t20260102T030000-1-1.tsv\nrow\t" + a + "\nrow\t" + b + "\n" +
		"invalid\t20260101T030000-1-1.tsv\n" +
		"point\t20260101T020000-1-1.tsv\nrow\t" + a + "\n"
	r := &scriptRunner{answers: map[string]string{"history": out, "state": a + "\n" + b2 + "\n"}}
	m := &Manager{Runner: r}
	v, e := m.history(context.Background(), Request{Action: "history"})
	if e != nil {
		t.Fatal(e)
	}
	view := v.(HistoryView)
	if view.Total != 3 || len(view.Entries) != 3 || view.Revision != revision {
		t.Fatalf("view = %+v", view)
	}
	newest := view.Entries[0]
	if !newest.Time.Equal(time.Date(2026, 1, 2, 3, 0, 0, 0, time.UTC)) || len(newest.Changes) != 1 || newest.Changes[0].Kind != "changed" || strings.Join(newest.Changes[0].Fields, ",") != "enabled,destinations" {
		t.Fatalf("newest = %+v", newest)
	}
	if !view.Entries[1].Invalid {
		t.Fatal("invalid point not marked")
	}
	// The oldest point pairs with the next valid newer state: B was added.
	if c := view.Entries[2].Changes; len(c) != 1 || c[0].Kind != "added" || c[0].ID != "F000002" {
		t.Fatalf("oldest = %+v", view.Entries[2])
	}
	got, e := m.history(context.Background(), Request{Action: "history-review", History: HistoryInput{Point: "20260101T020000-1-1.tsv"}})
	if e != nil {
		t.Fatal(e)
	}
	review := got.(HistoryReview)
	if review.Count != 1 || len(review.Changes) != 1 || review.Changes[0].Kind != "removed" {
		t.Fatalf("review = %+v", review)
	}
	if _, e = m.history(context.Background(), Request{Action: "history-restore", History: HistoryInput{Point: "../x", Revision: revision}}); e == nil {
		t.Fatal("bad point accepted")
	}
	if _, e = m.history(context.Background(), Request{Action: "history-restore", History: HistoryInput{Point: "20260101T020000-1-1.tsv", Revision: revision}}); e != nil {
		t.Fatal(e)
	}
	if last := r.calls[len(r.calls)-1]; last != "history-restore 20260101T020000-1-1.tsv "+revision {
		t.Fatalf("call = %q", last)
	}
}

func TestDiagnoseParsesChecksAndProbes(t *testing.T) {
	checks, probes := parseDiagnosis("check\tenabled\tok\t\ncheck\trules\tfail\tnftables\ncheck\tx\tbogus\t\nprobe\ttcp\t192.0.2.1\t443\tdestination\nprobe\tudp\t192.0.2.2\t53\tdestination\n")
	if len(checks) != 2 || len(probes) != 2 || worst(checks) != "fail" || probes[1].kind != "udp" {
		t.Fatalf("checks %+v probes %+v", checks, probes)
	}
	if _, e := (&Manager{Runner: &scriptRunner{}}).diagnose(context.Background(), "rm -rf"); e == nil {
		t.Fatal("invalid owner accepted")
	}
}

func TestSnapshotScheduleAndStore(t *testing.T) {
	loc, _ := time.LoadLocation("Asia/Tehran")
	if loc == nil {
		loc = time.UTC
	}
	s := SnapshotSettings{Frequency: "daily", Time: "03:30", Keep: 2}
	after := time.Date(2026, 1, 5, 0, 0, 0, 0, loc)
	if got := nextSnapshot(s, after, loc); !got.Equal(time.Date(2026, 1, 5, 3, 30, 0, 0, loc).UTC()) {
		t.Fatalf("daily next = %v", got)
	}
	s.Frequency, s.Weekday = "weekly", 0
	if got := nextSnapshot(s, after, loc); got.In(loc).Weekday() != time.Sunday || !got.After(after) {
		t.Fatalf("weekly next = %v", got.In(loc))
	}
	for _, bad := range []SnapshotSettings{{Frequency: "hourly", Time: "03:00", Keep: 1}, {Frequency: "daily", Time: "3:00", Keep: 1}, {Frequency: "daily", Time: "03:00", Keep: 0}, {Frequency: "weekly", Time: "03:00", Weekday: 7, Keep: 1}} {
		if bad.Validate() == nil {
			t.Fatalf("accepted %+v", bad)
		}
	}
	dir := t.TempDir()
	store, e := OpenSnapshots(filepath.Join(dir, "snapshots.json"), filepath.Join(dir, "snapshots"))
	if e != nil {
		t.Fatal(e)
	}
	now := time.Date(2026, 1, 5, 0, 0, 0, 0, time.UTC)
	if e = store.Configure(now, SnapshotSettings{Enabled: true, Frequency: "daily", Time: "03:30", Keep: 2}, 0); e != nil {
		t.Fatal(e)
	}
	if store.Due(now.Add(time.Hour), time.UTC) || !store.Due(now.Add(4*time.Hour), time.UTC) {
		t.Fatal("due window wrong")
	}
	doc := recoveryDocument{Version: 1, Created: now, Connections: []model.Connection{}, Resources: []BackupResource{}}
	for i := 0; i < 3; i++ {
		if _, e = store.write(now.Add(time.Duration(i)*time.Hour), doc, 2); e != nil {
			t.Fatal(e)
		}
	}
	list := store.list()
	if len(list) != 2 || list[0].Name != "gtm-20260105T020000.json" {
		t.Fatalf("list = %+v", list)
	}
	if info, _ := os.Stat(filepath.Join(dir, "snapshots", list[0].Name)); info.Mode().Perm() != 0600 && os.PathSeparator == '/' {
		t.Fatalf("mode = %v", info.Mode())
	}
	store.record(now.Add(4*time.Hour), nil)
	if store.Due(now.Add(5*time.Hour), time.UTC) {
		t.Fatal("ran twice for one schedule")
	}
	if _, e = store.read("../../etc/passwd"); e == nil || store.remove("x.json") == nil {
		t.Fatal("invalid names accepted")
	}
	if e = store.remove(list[1].Name); e != nil || len(store.list()) != 1 {
		t.Fatal("remove failed")
	}
}

func TestPrometheusTokenAndExposition(t *testing.T) {
	p, _ := OpenPrometheus(filepath.Join(t.TempDir(), "prometheus.json"))
	if p.Allowed("") || p.Allowed("gtm_x") {
		t.Fatal("disabled endpoint allowed a scrape")
	}
	v, e := p.Configure(PrometheusInput{Enabled: true})
	if e != nil || !strings.HasPrefix(v.Token, "gtm_") || !p.Allowed(v.Token) || p.Allowed(v.Token+"x") {
		t.Fatalf("configure = %+v, %v", v, e)
	}
	if again := p.View(); again.Token != "" || !again.TokenSet {
		t.Fatal("token returned twice")
	}
	if _, e = p.Configure(PrometheusInput{Enabled: false, Revision: 1}); e != nil || p.Allowed(v.Token) {
		t.Fatal("disable kept the endpoint open")
	}
	latency, uptime := 12.5, 99.0
	cpu := 7.0
	view := health.View{Settings: health.Settings{Enabled: true}, Owners: []health.OwnerView{{Owner: "F000001", Name: `A "quoted"`, Engine: "nftables", Status: "up", Latency: &latency, Uptime24h: &uptime}, {Owner: "F000002", Status: "unknown"}}}
	text := prometheusText("edge", &view, &MetricsView{Counters: map[string]Traffic{"F000001": {Received: 10, Sent: 20}}}, HostTelemetry{CPU: &cpu, MemoryTotal: 100, MemoryAvailable: 40}, 3)
	for _, want := range []string{
		"# TYPE gtm_connection_up gauge\n",
		`gtm_connection_up{engine="nftables",id="F000001",name="A \"quoted\""} 1`,
		`gtm_connection_uptime_ratio_24h{engine="nftables",id="F000001",name="A \"quoted\""} 0.99`,
		`gtm_traffic_sent_bytes_total{id="F000001"} 20`,
		"gtm_host_cpu_percent 7\n", "gtm_notifications_unread 3\n",
	} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q in\n%s", want, text)
		}
	}
	if strings.Contains(text, `id="F000002"`) {
		t.Fatal("unknown status exported as a value")
	}
}

type fixedPinger struct{ n int }

func (f *fixedPinger) Probe(context.Context, health.Target) health.Result {
	f.n++
	if f.n == 3 {
		return health.Result{Error: "timeout"}
	}
	return health.Result{OK: true, RTT: float64(10 + f.n%2*4)}
}

func TestQualityAndGREUnitParsing(t *testing.T) {
	r := runQuality(context.Background(), &fixedPinger{}, "gre-tun-1", "10.0.1.2", 0)
	if r.Sent != 20 || r.Received != 19 || r.Loss != 5 || *r.Min != 10 || *r.Max != 14 || r.Jitter == nil || len(r.Samples) != 20 || r.Samples[2] != -1 {
		t.Fatalf("quality = %+v", r)
	}
	dir := t.TempDir()
	unit := "ExecStart=/sbin/ip tunnel add gre-out-7 mode gre remote 198.51.100.5 local 203.0.113.10 ttl 255 key 7\n"
	os.WriteFile(filepath.Join(dir, "gre-tun-7.service"), []byte(unit), 0644)
	os.WriteFile(filepath.Join(dir, "gre-tun-8.service"), []byte("ExecStart=/bin/true\n"), 0644)
	u, e := parseGREUnit(filepath.Join(dir, "gre-tun-7.service"))
	if e != nil || u.Iface != "gre-out-7" || u.Address != "10.0.7.2" || u.Peer != "10.0.7.1" || u.Remote != "198.51.100.5" {
		t.Fatalf("unit = %+v, %v", u, e)
	}
	if units := (&Manager{UnitDir: dir}).greUnits(); len(units) != 1 {
		t.Fatalf("units = %+v", units)
	}
}

func TestHealthEventsAndOptimizeWatch(t *testing.T) {
	c := notify.New()
	now := time.Now().UTC()
	before := map[string]health.OwnerState{"F1": {Owner: "F1", Name: "A", Status: health.StatusUp}, "F2": {Owner: "F2", Name: "B", Status: health.StatusDown, Since: now.Add(-5 * time.Minute)}}
	after := map[string]health.OwnerState{"F1": {Owner: "F1", Name: "A", Status: health.StatusDown, Endpoint: "192.0.2.1:443", Error: "timeout"}, "F2": {Owner: "F2", Name: "B", Status: health.StatusUp}, "F3": {Owner: "F3", Status: health.StatusUp}}
	healthEvents(c, now, before, after)
	v := c.View()
	if len(v.Events) != 2 {
		t.Fatalf("events = %+v", v.Events)
	}
	kinds := v.Events[0].Kind + "," + v.Events[1].Kind
	if kinds != "up,down" && kinds != "down,up" {
		t.Fatalf("kinds = %s", kinds)
	}

	// The watch undoes the guarded step when a baseline owner goes down.
	h := health.New()
	s := maintenance.New()
	o := newOperations(h, s)
	o.Notify = notify.New()
	if e := h.Configure(now, health.Settings{Enabled: true, Interval: 30, FailThreshold: 1, RecoverThreshold: 1, RetentionDays: 7, Failover: []string{}, FailoverInterval: 5}, 0); e != nil {
		t.Fatal(e)
	}
	target := health.Target{Key: "F1|tcp", Owner: "F1", Name: "A", Engine: "nftables", Kind: health.KindTCP, Address: "192.0.2.1", Port: 443}
	h.Record(now, []health.Target{target}, map[string]health.Result{"F1|tcp": {OK: true, RTT: 5}}, nil)
	o.startWatch(now, 10, 1700000000)
	h.Record(now.Add(time.Minute), []health.Target{target}, map[string]health.Result{"F1|tcp": {Error: "timeout"}}, nil)
	status := "meta\tsteps\t1\nmeta\tlast\t1700000000\nmeta\tfile\t/etc/sysctl.d/zz.conf\n"
	r := &scriptRunner{answers: map[string]string{"optimize-status": status, "optimize-undo": "Undid the last step.\n"}}
	m := &Manager{Runner: r, Ops: o}
	o.checkWatch(context.Background(), m, &sync.Mutex{})
	w := o.watchView(time.Now().UTC())
	if w == nil || w.Result != WatchUndone || len(w.Down) != 1 || r.calls[len(r.calls)-1] != "optimize-undo" {
		t.Fatalf("watch = %+v calls %v", w, r.calls)
	}
	if e := o.Notify.View().Events[0]; e.Kind != notify.KindRollback {
		t.Fatalf("event = %+v", e)
	}
	data, _ := json.Marshal(w)
	if !strings.Contains(string(data), `"result":"undone"`) {
		t.Fatal(string(data))
	}
}
