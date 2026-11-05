package control

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/maintenance"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func TestGREPeerFromModernAndLegacyUnits(t *testing.T) {
	cases := map[string]string{
		"ExecStart=/sbin/ip addr add 10.0.7.2/30 dev gre-out-7\n": "10.0.7.1",
		"ExecStart=/sbin/ip addr add 10.0.7.1/30 dev gre7\n":      "10.0.7.2",
		"ExecStart=/sbin/ip addr add 10.12.34.1/30 dev gre-out-3": "10.12.34.2",
		"ExecStart=/sbin/ip addr add 10.0.7.3/30 dev gre7\n":      "",
		"no address": "",
	}
	for unit, want := range cases {
		if got := grePeer(unit); got != want {
			t.Errorf("grePeer(%q) = %q, want %q", unit, got, want)
		}
	}
}

func TestHealthTargetsCoverEveryEngine(t *testing.T) {
	inventory := Inventory{
		Connections: []model.Connection{
			{ID: "F000001", Name: "Reality", Engine: "nftables", Protocol: "tcp", Ports: "443", Enabled: true, Targets: []model.Target{{IP: "198.51.100.20", Port: 443}, {IP: "198.51.100.20", Port: 443}, {IP: "2001:db8::20"}}},
			{ID: "F000002", Engine: "iptables", Protocol: "udp", Ports: "51820", Enabled: true, Targets: []model.Target{{IP: "198.51.100.30", Port: 51820}}},
			{ID: "F000003", Engine: "haproxy", Protocol: "tcp", Ports: "8443", Enabled: true, Status: "failed", Targets: []model.Target{{IP: "198.51.100.40", Port: 8443}}},
			{ID: "F000004", Engine: "realm", Protocol: "tcp", Ports: "9000", Enabled: false, Targets: []model.Target{{IP: "198.51.100.50", Port: 9000}}},
		},
		Resources: []Resource{{ID: "gre-tun-7", Engine: "gre", Name: "GRE 7", Status: "active", Peer: "10.0.7.1"}, {ID: "gtm-frp-entrance-edge", Engine: "frp", Status: "inactive"}},
	}
	targets := healthTargets(inventory)
	keys := []string{}
	for _, target := range targets {
		keys = append(keys, target.Key)
	}
	want := []string{
		"F000001|tcp|198.51.100.20|443", "F000001|tcp|2001:db8::20|443",
		"F000002|icmp|198.51.100.30",
		"F000003|service", "F000003|tcp|198.51.100.40|8443",
		"gre-tun-7|service", "gre-tun-7|icmp|10.0.7.1",
		"gtm-frp-entrance-edge|service",
	}
	if strings.Join(keys, " ") != strings.Join(want, " ") {
		t.Fatalf("targets:\n%v\nwant:\n%v", keys, want)
	}
	if targets[0].Name != "Reality" || targets[2].Name != "F000002" {
		t.Fatal("display names fall back to IDs")
	}
	results := serviceResults(inventory, targets)
	if !results["gre-tun-7|service"].OK || results["F000003|service"].Error != "failed" || results["gtm-frp-entrance-edge|service"].Error != "inactive" {
		t.Fatalf("service results = %+v", results)
	}
}

func TestMaintainUsesOnlyAllowlistedCommands(t *testing.T) {
	units := t.TempDir()
	for _, unit := range []string{"gtm-F000003", "gtm-F000004", "gre-tun-7"} {
		if e := os.WriteFile(filepath.Join(units, unit+".service"), []byte("[Unit]\n"), 0600); e != nil {
			t.Fatal(e)
		}
	}
	runner := &fakeRunner{}
	m := &Manager{Runner: runner, UnitDir: units}
	ctx := context.Background()
	refreshed := false
	kernel := maintenance.Owner{ID: "F000001", Engine: "nftables"}
	if _, e := m.maintain(ctx, maintenance.ActionRefresh, kernel, &refreshed); e != nil {
		t.Fatal(e)
	}
	if out, e := m.maintain(ctx, maintenance.ActionRefresh, maintenance.Owner{ID: "F000002", Engine: "iptables"}, &refreshed); e != nil || !strings.Contains(out, "already") {
		t.Fatalf("second kernel refresh should be collapsed: %q %v", out, e)
	}
	steps := []struct {
		action string
		owner  maintenance.Owner
	}{
		{maintenance.ActionRestart, kernel},
		{maintenance.ActionRefresh, maintenance.Owner{ID: "F000003", Engine: "haproxy"}},
		{maintenance.ActionRestart, maintenance.Owner{ID: "F000004", Engine: "realm"}},
		{maintenance.ActionRestart, maintenance.Owner{ID: "gre-tun-7", Engine: "gre"}},
	}
	for _, step := range steps {
		if _, e := m.maintain(ctx, step.action, step.owner, &refreshed); e != nil {
			t.Fatalf("%s %s: %v", step.action, step.owner.ID, e)
		}
	}
	got := []string{}
	for _, call := range runner.calls {
		got = append(got, strings.TrimSpace(call))
	}
	want := []string{
		"/bin/bash " + ManagerPath + " --api kernel-refresh",
		"/bin/bash " + ManagerPath + " --api flows-reset F000001",
		"systemctl reload gtm-F000003",
		"systemctl restart gtm-F000004",
		"systemctl restart gre-tun-7",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if _, e := m.maintain(ctx, maintenance.ActionRefresh, maintenance.Owner{ID: "F000004", Engine: "realm"}, &refreshed); e == nil {
		t.Fatal("realm has no graceful reload")
	}
	if _, e := m.maintain(ctx, maintenance.ActionRestart, maintenance.Owner{ID: "gtm-frp-entrance-gone", Engine: "frp"}, &refreshed); e == nil {
		t.Fatal("missing unit accepted")
	}
	if _, e := m.maintain(ctx, maintenance.ActionRestart, maintenance.Owner{ID: "sshd", Engine: "gre"}, &refreshed); e == nil {
		t.Fatal("unmanaged unit accepted")
	}
}

func TestPeriodTrafficHandlesCycleResets(t *testing.T) {
	from := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	old, fresh := from.Add(-48*time.Hour), from.Add(24*time.Hour)
	points := []TrafficPoint{
		{Time: from.Add(-time.Hour), Received: 100, Sent: 10, CycleStart: old},
		{Time: from.Add(time.Hour), Received: 150, Sent: 15, CycleStart: old},
		{Time: fresh.Add(time.Hour), Received: 30, Sent: 3, CycleStart: fresh},
		{Time: fresh.Add(2 * time.Hour), Received: 70, Sent: 7, CycleStart: fresh},
		{Time: from.Add(8 * 24 * time.Hour), Received: 999, Sent: 99, CycleStart: fresh},
	}
	rx, tx, ok := periodTraffic(points, from, from.Add(7*24*time.Hour))
	if !ok || rx != 50+30+40 || tx != 5+3+4 {
		t.Fatalf("period traffic = %d %d %v", rx, tx, ok)
	}
	if _, _, ok := periodTraffic(points, from.Add(30*24*time.Hour), from.Add(31*24*time.Hour)); ok {
		t.Fatal("an empty window has no total")
	}
}

func TestOperationsUnavailableWithoutOps(t *testing.T) {
	if _, e := (&Manager{}).Execute(context.Background(), Request{Action: "health"}); e == nil {
		t.Fatal("agent brokers must refuse health")
	}
	for _, action := range []string{"health", "health-report", "maintenance"} {
		if !ReadAction(action) || PublicOperation(action) {
			t.Fatal("read action misclassified:", action)
		}
	}
	for _, action := range []string{"health-configure", "maintenance-save", "maintenance-run", "maintenance-cancel", "maintenance-delete", "maintenance-configure"} {
		if ReadAction(action) || !PublicOperation(action) {
			t.Fatal("mutation misclassified:", action)
		}
	}
}

func TestOperationsPersistAcrossRestart(t *testing.T) {
	directory := t.TempDir()
	o, e := NewOperations(directory)
	if e != nil {
		t.Fatal(e)
	}
	now := time.Now().UTC()
	s := health.Defaults()
	s.Enabled = true
	if _, e = o.execute(now, Request{Action: "health-configure", Health: HealthInput{Settings: s}}, nil); e != nil {
		t.Fatal(e)
	}
	plan := maintenance.Plan{Name: "Nightly", Enabled: true, Action: maintenance.ActionRestart, Trigger: maintenance.Trigger{Kind: maintenance.TriggerDaily, Times: []string{"04:30"}}, Guards: maintenance.Guards{MaxPerDay: 1}}
	if _, e = o.execute(now, Request{Action: "maintenance-save", Maintenance: MaintenanceInput{Plan: &plan}}, nil); e != nil {
		t.Fatal(e)
	}
	again, e := NewOperations(directory)
	if e != nil {
		t.Fatal(e)
	}
	if !again.Health.Settings().Enabled || len(again.Maintenance.View(now).Plans) != 1 {
		t.Fatal("operations state was not persisted")
	}
	if _, e = again.execute(now, Request{Action: "health-report", Health: HealthInput{Week: 99}}, nil); e == nil {
		t.Fatal("out-of-range report accepted")
	}
}

func TestDemoOperationsAreSimulated(t *testing.T) {
	d := NewDemo()
	ctx := context.Background()
	raw, e := d.Do(ctx, Request{Action: "health"})
	if e != nil {
		t.Fatal(e)
	}
	var view HealthView
	if e = json.Unmarshal(raw, &view); e != nil || len(view.Owners) < 4 || view.Summary.Uptime7d == nil || view.Host == nil {
		t.Fatalf("demo health = %+v %v", view.Summary, e)
	}
	raw, e = d.Do(ctx, Request{Action: "health-report", Health: HealthInput{Week: 1, WeekStart: 6}})
	if e != nil {
		t.Fatal(e)
	}
	var report HealthReport
	if e = json.Unmarshal(raw, &report); e != nil || len(report.Rows) == 0 || report.Uptime == nil {
		t.Fatalf("demo report = %+v %v", report, e)
	}
	raw, e = d.Do(ctx, Request{Action: "maintenance"})
	if e != nil {
		t.Fatal(e)
	}
	var plans MaintenanceView
	if e = json.Unmarshal(raw, &plans); e != nil || len(plans.Plans) != 3 {
		t.Fatalf("demo plans = %+v %v", plans, e)
	}
	before := len(plans.History)
	raw, e = d.Do(ctx, Request{Action: "maintenance-run", Maintenance: MaintenanceInput{ID: plans.Plans[0].ID}})
	if e != nil {
		t.Fatal(e)
	}
	if e = json.Unmarshal(raw, &plans); e != nil || len(plans.History) <= before || !strings.HasPrefix(plans.History[0].Message, "Demo") {
		t.Fatalf("demo run history = %+v %v", plans.History, e)
	}
}
