package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

type fakeRunner struct {
	calls     []string
	state     string
	failApply bool
	counter   uint64
	exists    bool
}

func (f *fakeRunner) Run(_ context.Context, name string, args []string, input string) (string, error) {
	f.calls = append(f.calls, name+" "+strings.Join(args, " ")+"\n"+input)
	if name == "/bin/bash" {
		if len(args) > 2 && args[2] == "state" {
			return f.state, nil
		}
		return "applied", nil
	}
	if name == "nft" {
		if len(args) > 0 && args[0] == "-j" {
			if !f.exists {
				return "", errors.New("missing")
			}
			return `{ "nftables": [{"counter":{"name":"F000001_rx","bytes":` + fmtUint(f.counter) + `}}, {"counter":{"name":"F000001_tx","bytes":50}}]}`, nil
		}
		if len(args) > 0 && args[0] == "list" {
			if !f.exists {
				return "", errors.New("missing")
			}
			return "table", nil
		}
		if f.failApply {
			return "bad native syntax", errors.New("rejected")
		}
		if args[0] == "-f" {
			f.exists = strings.Contains(input, "table inet "+metricsTable+" {")
			f.counter = 0
		}
		return "", nil
	}
	return "", nil
}
func fmtUint(n uint64) string { b, _ := json.Marshal(n); return string(b) }
func stateFixture() string {
	return "F000001\tExample\tnftables\tboth\t192.0.2.10\t28443\tsingle\t1\tmasquerade\ttm_in\t203.0.113.20:28001@1\t1"
}
func TestChangesUseRevisionsAndFixedCommands(t *testing.T) {
	runner := &fakeRunner{state: stateFixture()}
	m := &Manager{Runner: runner}
	_, e := m.Execute(context.Background(), Request{Action: "delete", Selected: []Selection{{ID: "F000001", Revision: "stale"}}})
	if e == nil || len(runner.calls) != 1 {
		t.Fatal("stale change mutated", e, runner.calls)
	}
	runner.calls = nil
	_, e = m.Execute(context.Background(), Request{Action: "delete", Selected: []Selection{{ID: "F000001", Revision: model.Revision(stateFixture())}}})
	if e != nil || len(runner.calls) != 2 || !strings.Contains(runner.calls[1], "--api delete\n"+stateFixture()) {
		t.Fatal(e, runner.calls)
	}
	_, e = m.Execute(context.Background(), Request{Action: "service", Service: "ssh", Verb: "stop"})
	if e == nil {
		t.Fatal("unmanaged service accepted")
	}
	_, e = m.Execute(context.Background(), Request{Action: "install", Components: []string{"haproxy;id"}})
	if e == nil {
		t.Fatal("shell input accepted")
	}
}
func TestMetricsNativeRulesAndOffPath(t *testing.T) {
	connections, _, e := model.ParseState(stateFixture())
	if e != nil {
		t.Fatal(e)
	}
	inventory := Inventory{Connections: connections}
	rules := MetricsRules(inventory, MetricsSettings{Enabled: true, Interval: 60})
	for _, text := range []string{"ct direction original", "ct direction reply", "ct original ip daddr 192.0.2.10", "proto-dst 28443", "iifname \"tm_in\"", "oifname \"tm_in\"", "counter name F000001_rx"} {
		if !strings.Contains(rules, text) {
			t.Fatal(text, rules)
		}
	}
	if strings.Contains(rules, "flush ruleset") {
		t.Fatal("host flush")
	}
	runner := &fakeRunner{}
	metrics, e := NewMetrics(runner, filepath.Join(t.TempDir(), "metrics.json"))
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 5; i++ {
		if e = metrics.Tick(context.Background(), inventory); e != nil {
			t.Fatal(e)
		}
	}
	if len(runner.calls) != 0 {
		t.Fatal("disabled metrics ran commands", runner.calls)
	}
}
func TestMetricsTotalsSurviveResetDisableAndRestart(t *testing.T) {
	connections, _, _ := model.ParseState(stateFixture())
	inventory := Inventory{Connections: connections}
	runner := &fakeRunner{}
	path := filepath.Join(t.TempDir(), "metrics.json")
	m, _ := NewMetrics(runner, path)
	if _, e := m.Configure(context.Background(), MetricsSettings{Enabled: true, Interval: 15, IDs: []string{}}, inventory); e != nil {
		t.Fatal(e)
	}
	runner.counter = 100

	if e := m.Tick(context.Background(), inventory); e != nil {
		t.Fatal(e)
	}
	v := m.View()
	if v.Counters["F000001"].Received != 100 {
		t.Fatal(v)
	}
	runner.counter = 130

	_ = m.Tick(context.Background(), inventory)
	if m.View().Counters["F000001"].Received != 130 {
		t.Fatal(m.View())
	}
	restarted, e := NewMetrics(runner, path)
	if e != nil {
		t.Fatal(e)
	}
	runner.counter = 150

	if e = restarted.Tick(context.Background(), inventory); e != nil {
		t.Fatal(e)
	}
	if restarted.View().Counters["F000001"].Received != 150 {
		t.Fatal("restart lost or doubled totals", restarted.View())
	}
	runner.counter = 20

	_ = restarted.Tick(context.Background(), inventory)
	if restarted.View().Counters["F000001"].Received != 170 {
		t.Fatal("reset lost totals", restarted.View())
	}
	if _, e = restarted.Configure(context.Background(), MetricsSettings{Enabled: false, Interval: 60, IDs: []string{}}, inventory); e != nil {
		t.Fatal(e)
	}
	calls := len(runner.calls)
	_ = restarted.Tick(context.Background(), inventory)
	if len(runner.calls) != calls || runner.exists {
		t.Fatal("off path retained kernel rules")
	}
}
func TestMetricsFailureKeepsSettings(t *testing.T) {
	runner := &fakeRunner{failApply: true}
	m, _ := NewMetrics(runner, filepath.Join(t.TempDir(), "metrics.json"))
	connections, _, _ := model.ParseState(stateFixture())
	_, e := m.Configure(context.Background(), MetricsSettings{Enabled: true, Interval: 60}, Inventory{Connections: connections})
	if e == nil || m.Enabled() {
		t.Fatal("failed configuration was committed")
	}
}
func TestReverseValidationAndListenerInventory(t *testing.T) {
	r := Reverse{Engine: "frp", Name: "example", Role: "entrance", Host: "192.0.2.10", Control: 7000, Public: 443, LocalIP: "127.0.0.1", LocalPort: 8443, Protocol: "tcp", Transport: "tcp", Token: "abcdefghijklmnopqrstuvwxyz123456", Group: "group", Internal: 7001}
	input, e := r.Input()
	if e != nil || strings.Contains(input, "\n\n") {
		t.Fatal(e)
	}
	r.Token = "$(id)"
	if _, e = r.Input(); e == nil {
		t.Fatal("bad token accepted")
	}
	directory := t.TempDir()
	resource := Resource{ID: "gtm-frp-entrance-example", Engine: "frp", Role: "entrance"}
	os.WriteFile(filepath.Join(directory, resource.ID+".toml"), []byte("proxyBindAddr = \"192.0.2.10\"\nallowPorts = [{ single = 443 }]\n"), 0600)
	readReverseListener(directory, &resource)
	if resource.Port != 443 || resource.Bind != "192.0.2.10" {
		t.Fatal(resource)
	}
}
