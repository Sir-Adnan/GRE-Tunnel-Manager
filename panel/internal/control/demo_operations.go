package control

import (
	"encoding/json"
	"hash/fnv"
	"math"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/maintenance"
)

// Demo health and maintenance are simulated: probe results are generated,
// plans "run" without touching the system, and every record says so.
const demoMessage = "Demo: simulated, nothing was changed."

type demoOps struct {
	ops  *Operations
	last time.Time
}

func demoSeed(key string) float64 {
	h := fnv.New32a()
	_, _ = h.Write([]byte(key))
	return float64(h.Sum32()%1000) / 1000
}

// demoResults returns deterministic, slightly varying RTTs and one outage
// window, so the uptime bars and reports have something to show.
func demoResults(targets []health.Target, at time.Time) map[string]health.Result {
	out := map[string]health.Result{}
	hoursAgo := time.Since(at).Hours()
	for _, t := range targets {
		seed := demoSeed(t.Key)
		if t.Kind == health.KindService {
			out[t.Key] = health.Result{OK: true}
			continue
		}
		if t.Owner == "F000002" && hoursAgo > 49 && hoursAgo < 49.5 {
			out[t.Key] = health.Result{Error: "timeout"}
			continue
		}
		base := 35 + 60*seed
		wave := 6 * math.Sin(float64(at.Unix())/5400+seed*6)
		evening := 0.0
		if h := at.In(time.UTC).Hour(); h >= 16 && h <= 19 {
			evening = 25 * seed
		}
		out[t.Key] = health.Result{OK: true, RTT: math.Round((base+wave+evening)*10) / 10}
	}
	return out
}

func demoHost(at time.Time) *health.HostSnapshot {
	count, maximum, buckets, timeout := uint64(23517), uint64(262144), uint64(65536), uint64(3600)
	percent := math.Round(1000*float64(count)/float64(maximum)) / 10
	cpu, steal, softirq, iowait := 14.2, 0.8, 3.1, 0.2
	return &health.HostSnapshot{Time: at, ConntrackCount: &count, ConntrackMax: &maximum, ConntrackPercent: &percent, Hashsize: &buckets, EstablishedTimeout: &timeout, CPU: &cpu, Steal: &steal, SoftIRQ: &softirq, IOWait: &iowait, ConntrackCLI: true, Hints: []string{}}
}

func newDemoOps(inventory Inventory) *demoOps {
	h, s := health.New(), maintenance.New()
	o := newOperations(h, s)
	o.uptime = func() (time.Duration, bool) { return 72 * time.Hour, true }
	o.lookPath = func(string) (string, error) { return "/usr/sbin/conntrack", nil }
	now := time.Now().UTC()
	settings := health.Defaults()
	settings.Enabled = true
	_ = h.Configure(now, settings, 0)
	_ = s.Configure(maintenance.Settings{Enabled: true, Timezone: "Asia/Tehran"}, 0)
	inventory = demoResources(inventory)
	targets := healthTargets(inventory)
	for at := now.Add(-8 * 24 * time.Hour); at.Before(now); at = at.Add(10 * time.Minute) {
		h.Record(at, targets, demoResults(targets, at), demoHost(at))
	}
	plans := []maintenance.Plan{
		{Name: "Nightly flow reset", Enabled: true, Action: maintenance.ActionRestart, Scope: []string{"F000002"}, Trigger: maintenance.Trigger{Kind: maintenance.TriggerDaily, Times: []string{"04:30"}}, Guards: maintenance.Guards{QuietMbps: 20, QuietWait: 60, QuietTimeout: "skip", Cooldown: 360, MaxPerDay: 1, Stagger: 5}},
		{Name: "Heal GRE and services", Enabled: true, Action: maintenance.ActionRestart, Trigger: maintenance.Trigger{Kind: maintenance.TriggerHealth, Condition: maintenance.ConditionDown, Minutes: 3}, Guards: maintenance.Guards{Cooldown: 30, MaxPerDay: 6, Stagger: 5}},
		{Name: "Weekly reboot", Enabled: false, Action: maintenance.ActionReboot, Trigger: maintenance.Trigger{Kind: maintenance.TriggerWeekly, Days: []int{5}, Times: []string{"04:30"}}, Guards: maintenance.Guards{Cooldown: 1440, MaxPerDay: 1, MinUptime: 30, Notice: 5}},
	}
	for i, p := range plans {
		stored, e := s.Save(now.Add(-7*24*time.Hour), p, uint64(i+1))
		if e != nil {
			continue
		}
		at := now.Add(-time.Duration(48-24*i) * time.Hour)
		owners := []maintenance.Owner{{ID: "F000002", Name: "WireGuard Stockholm", Engine: "nftables"}}
		if i == 1 {
			owners = []maintenance.Owner{{ID: "gre-tun-7", Name: "GRE 7", Engine: "gre"}}
		}
		if i < 2 {
			_ = s.Finish(maintenance.Run{Plan: stored, Owners: owners, Reason: []string{"schedule", "health"}[i]}, []maintenance.Entry{{Owner: owners[0].ID, OwnerName: owners[0].Name, Engine: owners[0].Engine, Started: at, Ended: at.Add(2 * time.Second), Result: maintenance.ResultOK, Message: demoMessage}})
		}
	}
	return &demoOps{ops: o, last: now}
}

// demoResources adds a simulated GRE link so health has every probe kind.
func demoResources(inventory Inventory) Inventory {
	for _, r := range inventory.Resources {
		if r.Engine == "gre" {
			return inventory
		}
	}
	next := inventory
	next.Resources = append(append([]Resource{}, inventory.Resources...), Resource{ID: "gre-tun-7", Engine: "gre", Name: "GRE 7", Role: "iran", Status: "active", Interface: "gre-out-7", Configured: true, Peer: "10.0.7.1"})
	return next
}

type demoEnv struct {
	o         *Operations
	inventory Inventory
}

func (e demoEnv) Owners() []maintenance.Owner { return maintenanceOwners(e.inventory) }
func (e demoEnv) Uptime() time.Duration       { return 72 * time.Hour }
func (e demoEnv) Throughput() (float64, bool) { return 12, true }
func (e demoEnv) HealthEnabled() bool         { return e.o.Health.Settings().Enabled }
func (e demoEnv) Health(owner string) (bool, bool, float64) {
	h := e.o.Health.Owner(owner)
	return h.Known, h.Down, h.Latency
}

// operations serves the health and maintenance actions inside the demo.
func (d *Demo) operations(r Request) (json.RawMessage, error) {
	inventory := demoResources(d.inventory)
	if d.ops == nil {
		d.ops = newDemoOps(inventory)
	}
	o := d.ops.ops
	now := time.Now().UTC()
	if s := o.Health.Settings(); s.Enabled && now.Sub(d.ops.last) >= time.Duration(s.Interval)*time.Second {
		targets := healthTargets(inventory)
		o.Health.Record(now, targets, demoResults(targets, now), demoHost(now))
		d.ops.last = now
	}
	result, e := o.execute(now, r, nil)
	if e != nil {
		return nil, e
	}
	// Due and queued runs complete at once, simulated.
	for _, run := range o.Maintenance.Evaluate(now, demoEnv{o: o, inventory: inventory}) {
		entries := []maintenance.Entry{}
		if run.Plan.Action == maintenance.ActionReboot {
			entries = append(entries, maintenance.Entry{Started: now, Ended: now, Result: maintenance.ResultOK, Message: "Demo: a reboot was simulated; the server did not restart."})
		}
		for _, owner := range run.Owners {
			result := maintenance.ResultOK
			message := demoMessage
			if run.Plan.DryRun {
				result, message = maintenance.ResultDryRun, describe(run.Plan.Action, owner)
			}
			entries = append(entries, maintenance.Entry{Owner: owner.ID, OwnerName: owner.Name, Engine: owner.Engine, Started: now, Ended: now, Result: result, Message: message})
		}
		_ = o.Maintenance.Finish(run, entries)
		if r.Action == "maintenance-run" {
			result = o.maintenanceView(now)
		}
	}
	return json.Marshal(result)
}
