package control

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// counterRunner answers `nft -j list table` with the bytes it holds.
type counterRunner struct{ rx, tx uint64 }

func (r *counterRunner) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	if name != "nft" || len(args) < 2 || args[0] != "-j" {
		return "", errors.New("unexpected command")
	}
	return fmt.Sprintf(`{"nftables":[{"metainfo":{}},{"counter":{"family":"inet","name":"F000001_rx","bytes":%d}},{"counter":{"name":"F000001_tx","bytes":%d}},{"counter":{"name":"not-an-id!_rx","bytes":9}}]}`, r.rx, r.tx), nil
}

func TestLiveRatesNeedTwoSamplesAndSkipResets(t *testing.T) {
	runner := &counterRunner{rx: 1000, tx: 500}
	m := &Metrics{Runner: runner, nftActive: true, view: MetricsView{Settings: MetricsSettings{Enabled: true, Interval: 60}}}
	m.liveInterfaces = map[string]string{"G000001": "gre-tun-1"}
	gre := map[string]string{"/sys/class/net/gre-tun-1/statistics/rx_bytes": "100\n", "/sys/class/net/gre-tun-1/statistics/tx_bytes": "50\n"}
	read := func(path string) ([]byte, error) {
		if v, ok := gre[path]; ok {
			return []byte(v), nil
		}
		return nil, errors.New("missing")
	}
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	first := m.liveAt(context.Background(), start, read)
	if first.Window != 0 || len(first.Rates) != 0 || !first.Enabled {
		t.Fatalf("first sample must only set a baseline: %+v", first)
	}
	runner.rx, runner.tx = 3000, 1500
	gre["/sys/class/net/gre-tun-1/statistics/rx_bytes"] = "4100"
	second := m.liveAt(context.Background(), start.Add(2*time.Second), read)
	if second.Window != 2 {
		t.Fatalf("window = %v", second.Window)
	}
	if r := second.Rates["F000001"]; r.Received != 1000 || r.Sent != 500 {
		t.Fatalf("forward rate = %+v", r)
	}
	if r := second.Rates["G000001"]; r.Received != 2000 || r.Sent != 0 {
		t.Fatalf("GRE rate = %+v", r)
	}
	if _, ok := second.Rates["not-an-id!"]; ok {
		t.Fatal("invalid counter names must be ignored")
	}
	// A second viewer within the same second shares the sample.
	if again := m.liveAt(context.Background(), start.Add(2500*time.Millisecond), read); again.Time != second.Time {
		t.Fatal("concurrent viewers must share one sample")
	}
	// A rules reload resets the kernel counter: no negative or huge spike.
	runner.rx, runner.tx = 10, 10
	third := m.liveAt(context.Background(), start.Add(4*time.Second), read)
	if _, ok := third.Rates["F000001"]; ok {
		t.Fatalf("a reset counter must start a new baseline: %+v", third.Rates)
	}
	// Turning collection off answers without touching the kernel.
	m.view.Settings.Enabled = false
	m.Runner = nil
	off := m.liveAt(context.Background(), start.Add(6*time.Second), read)
	if off.Enabled || len(off.Rates) != 0 {
		t.Fatalf("collection off: %+v", off)
	}
}

func TestRememberInterfacesFollowsSelection(t *testing.T) {
	m := &Metrics{view: MetricsView{Settings: MetricsSettings{Enabled: true, IDs: []string{"G000002"}}}}
	inventory := Inventory{Resources: []Resource{
		{ID: "G000001", Engine: "gre", Interface: "gre-tun-1"},
		{ID: "G000002", Engine: "gre", Interface: "gre-tun-2"},
		{ID: "G000003", Engine: "gre", Interface: "bad name"},
	}}
	m.rememberInterfaces(inventory)
	if len(m.liveInterfaces) != 1 || m.liveInterfaces["G000002"] != "gre-tun-2" {
		t.Fatalf("interfaces = %v", m.liveInterfaces)
	}
	m.view.Settings.Enabled = false
	m.rememberInterfaces(inventory)
	if len(m.liveInterfaces) != 0 {
		t.Fatal("no interfaces while collection is off")
	}
}

func TestDemoLiveIsSteadyPerConnection(t *testing.T) {
	inventory := Inventory{Resources: []Resource{{ID: "G000001", Engine: "gre"}}}
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	on := demoLive(MetricsSettings{Enabled: true}, inventory, now)
	if r := on.Rates["G000001"]; r.Received <= 0 || r.Sent <= 0 {
		t.Fatalf("demo rate = %+v", r)
	}
	if off := demoLive(MetricsSettings{}, inventory, now); len(off.Rates) != 0 {
		t.Fatal("demo collection off must have no rates")
	}
	seeded := demoMetrics(inventory, now)
	if !seeded.Settings.Enabled || len(seeded.History["G000001"]) < 2 {
		t.Fatalf("demo metrics = %+v", seeded.Settings)
	}
}
