package control

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/maintenance"
)

// HealthInput carries health settings changes and report selection.
type HealthInput struct {
	Settings  health.Settings `json:"settings"`
	Revision  uint64          `json:"revision"`
	Week      int             `json:"week,omitempty"`
	WeekStart int             `json:"week_start,omitempty"`
	// Owner selects one connection or resource for on-demand reads.
	Owner string `json:"owner,omitempty"`
}

// MaintenanceInput carries one maintenance change. Exactly the fields an
// action needs are read; the revision guards every change.
type MaintenanceInput struct {
	Settings *maintenance.Settings `json:"settings,omitempty"`
	Plan     *maintenance.Plan     `json:"plan,omitempty"`
	ID       string                `json:"id,omitempty"`
	Revision uint64                `json:"revision"`
}

type HealthView struct {
	health.View
	Timezone string                    `json:"timezone"`
	Failover map[string]FailoverStatus `json:"failover"`
}

type MaintenanceView struct {
	maintenance.View
	Uptime        float64 `json:"uptime_seconds"`
	HealthEnabled bool    `json:"health_enabled"`
	ConntrackCLI  bool    `json:"conntrack_cli"`
}

type TrafficTotal struct {
	Received uint64 `json:"received"`
	Sent     uint64 `json:"sent"`
}

type HealthReport struct {
	health.Report
	Timezone    string                  `json:"timezone"`
	Maintenance []maintenance.Entry     `json:"maintenance"`
	Traffic     map[string]TrafficTotal `json:"traffic"`
}

// Operations owns the optional health monitor and maintenance scheduler.
// Both are off by default; while off they start no probes or subprocesses.
type Operations struct {
	Health      *health.Monitor
	Maintenance *maintenance.Scheduler
	host        *health.HostSampler
	prober      health.Prober
	// lookPath and uptime are replaceable for tests.
	lookPath func(string) (string, error)
	uptime   func() (time.Duration, bool)
	// runDir holds HAProxy stats sockets and the failover exclusion file.
	runDir   string
	failover failover

	mu          sync.Mutex
	inventory   Inventory
	inventoryAt time.Time
}

func NewOperations(directory string) (*Operations, error) {
	h, e := health.Open(filepath.Join(directory, "health.json"))
	if e != nil {
		return nil, fmt.Errorf("health history: %w", e)
	}
	s, e := maintenance.Open(filepath.Join(directory, "maintenance.json"))
	if e != nil {
		return nil, fmt.Errorf("maintenance plans: %w", e)
	}
	o := newOperations(h, s)
	if up, ok := o.uptime(); ok {
		_ = s.ResolveReboots(time.Now().Add(-up))
	}
	return o, nil
}

func newOperations(h *health.Monitor, s *maintenance.Scheduler) *Operations {
	return &Operations{Health: h, Maintenance: s, host: health.NewHostSampler(), prober: health.NetProber{Timeout: 3 * time.Second}, lookPath: exec.LookPath, uptime: systemUptime, runDir: "/run/gre-manager"}
}

func systemUptime() (time.Duration, bool) {
	data, e := os.ReadFile("/proc/uptime")
	if e != nil {
		return 0, false
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0, false
	}
	seconds, e := strconv.ParseFloat(f[0], 64)
	if e != nil {
		return 0, false
	}
	return time.Duration(seconds * float64(time.Second)), true
}

// invalidate drops the cached inventory after a mutation.
func (o *Operations) invalidate() {
	o.mu.Lock()
	o.inventoryAt = time.Time{}
	o.mu.Unlock()
}

func (o *Operations) cachedInventory(ctx context.Context, m *Manager, age time.Duration) (Inventory, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if !o.inventoryAt.IsZero() && time.Since(o.inventoryAt) < age {
		return o.inventory, nil
	}
	inventory, e := m.Inventory(ctx)
	if e != nil {
		return Inventory{}, e
	}
	o.inventory, o.inventoryAt = inventory, time.Now()
	return inventory, nil
}

func (o *Operations) conntrackCLI() bool {
	_, e := o.lookPath("conntrack")
	return e == nil
}

// healthRound records one probe round. A full round checks every target and
// samples the host; a fast round checks only destinations of forwards with
// failover. HAProxy destinations take the relay's own check results.
func (o *Operations) healthRound(ctx context.Context, m *Manager, now time.Time, full bool) (Inventory, error) {
	settings := o.Health.Settings()
	interval := time.Duration(settings.Interval) * time.Second
	inventory, e := o.cachedInventory(ctx, m, max(interval, 30*time.Second))
	if e != nil {
		return Inventory{}, e
	}
	targets := healthTargets(inventory)
	probe := targets
	if !full {
		selected := settings.FailoverSet()
		probe = []health.Target{}
		for _, t := range targets {
			if selected[t.Owner] && t.Kind != health.KindService {
				probe = append(probe, t)
			}
		}
	}
	results := o.haproxyResults(ctx, inventory, probe)
	rest := []health.Target{}
	for _, t := range probe {
		if _, ok := results[t.Key]; !ok {
			rest = append(rest, t)
		}
	}
	maps.Copy(results, health.Run(ctx, o.prober, rest, 8))
	var host *health.HostSnapshot
	if full {
		maps.Copy(results, serviceResults(inventory, targets))
		host = o.host.Sample(now)
		host.ConntrackCLI = o.conntrackCLI()
	}
	changed := o.Health.Record(now, targets, results, host)
	return inventory, o.Health.Flush(now, changed)
}

func (o *Operations) healthView(now time.Time) HealthView {
	loc := o.Maintenance.Location()
	return HealthView{View: o.Health.View(now, loc), Timezone: loc.String(), Failover: o.failover.view()}
}

func (o *Operations) report(now time.Time, input HealthInput, metrics *Metrics) (HealthReport, error) {
	if input.Week < 0 || input.Week > 13 || input.WeekStart < 0 || input.WeekStart > 6 {
		return HealthReport{}, errors.New("invalid report week")
	}
	loc := o.Maintenance.Location()
	r := HealthReport{Report: o.Health.Report(now, loc, time.Weekday(input.WeekStart), input.Week), Timezone: loc.String(), Traffic: map[string]TrafficTotal{}}
	r.Maintenance = o.Maintenance.History(r.Start, r.End)
	if metrics != nil {
		history := metrics.View().History
		for _, row := range r.Rows {
			if rx, tx, ok := periodTraffic(history[row.Owner], r.Start, r.End); ok {
				r.Traffic[row.Owner] = TrafficTotal{Received: rx, Sent: tx}
			}
		}
	}
	return r, nil
}

// periodTraffic sums cycle-relative samples inside [from, to). Cycle resets
// start from zero; the first sample of a cycle that began earlier only sets
// the baseline, so totals can undercount but never double count.
func periodTraffic(points []TrafficPoint, from, to time.Time) (rx, tx uint64, ok bool) {
	var previous *TrafficPoint
	for i := range points {
		p := &points[i]
		if p.Time.Before(from) {
			previous = p
			continue
		}
		if !p.Time.Before(to) {
			break
		}
		ok = true
		switch {
		case previous != nil && previous.CycleStart.Equal(p.CycleStart) && p.Received >= previous.Received && p.Sent >= previous.Sent:
			rx, tx = addTraffic(rx, p.Received-previous.Received), addTraffic(tx, p.Sent-previous.Sent)
		case !p.CycleStart.Before(from) || previous != nil:
			rx, tx = addTraffic(rx, p.Received), addTraffic(tx, p.Sent)
		}
		previous = p
	}
	return
}

func (o *Operations) maintenanceView(now time.Time) MaintenanceView {
	v := MaintenanceView{View: o.Maintenance.View(now), HealthEnabled: o.Health.Settings().Enabled, ConntrackCLI: o.conntrackCLI()}
	if up, ok := o.uptime(); ok {
		v.Uptime = math.Round(up.Seconds())
	}
	return v
}

// execute handles every operations action for the real manager and the demo.
func (o *Operations) execute(now time.Time, r Request, metrics *Metrics) (any, error) {
	in := r.Maintenance
	switch r.Action {
	case "health":
		return o.healthView(now), nil
	case "health-report":
		return o.report(now, r.Health, metrics)
	case "health-configure":
		if e := o.Health.Configure(now, r.Health.Settings, r.Health.Revision); e != nil {
			return nil, e
		}
		return o.healthView(now), nil
	case "maintenance":
		return o.maintenanceView(now), nil
	case "maintenance-configure":
		if in.Settings == nil {
			return nil, errors.New("settings required")
		}
		if e := o.Maintenance.Configure(*in.Settings, in.Revision); e != nil {
			return nil, e
		}
	case "maintenance-save":
		if in.Plan == nil {
			return nil, errors.New("plan required")
		}
		if _, e := o.Maintenance.Save(now, *in.Plan, in.Revision); e != nil {
			return nil, e
		}
	case "maintenance-delete":
		if e := o.Maintenance.Delete(in.ID, in.Revision); e != nil {
			return nil, e
		}
	case "maintenance-run":
		if e := o.Maintenance.Queue(now, in.ID); e != nil {
			return nil, e
		}
	case "maintenance-cancel":
		if e := o.Maintenance.Cancel(now, in.ID); e != nil {
			return nil, e
		}
	default:
		return nil, errors.New("unsupported operation")
	}
	return o.maintenanceView(now), nil
}

// opsEnv answers scheduling questions from cached inventory and live samples.
type opsEnv struct {
	ctx context.Context
	o   *Operations
	m   *Manager
}

func (e opsEnv) Owners() []maintenance.Owner {
	inventory, err := e.o.cachedInventory(e.ctx, e.m, 30*time.Second)
	if err != nil {
		return []maintenance.Owner{}
	}
	return maintenanceOwners(inventory)
}
func (e opsEnv) Uptime() time.Duration {
	up, _ := e.o.uptime()
	return up
}
func (e opsEnv) Throughput() (float64, bool) {
	s := e.m.telemetry.Sample()
	if s.Received == nil || s.Sent == nil {
		return 0, false
	}
	return (*s.Received + *s.Sent) * 8 / 1e6, true
}
func (e opsEnv) HealthEnabled() bool { return e.o.Health.Settings().Enabled }
func (e opsEnv) Health(owner string) (bool, bool, float64) {
	h := e.o.Health.Owner(owner)
	return h.Known, h.Down, h.Latency
}

// maintain performs one owner's step with existing allowlisted operations.
// refreshed collapses kernel reapplies: one apply covers every kernel forward.
func (m *Manager) maintain(ctx context.Context, action string, owner maintenance.Owner, refreshed *bool) (string, error) {
	unit := owner.ID
	switch owner.Engine {
	case "nftables", "iptables":
		if action == maintenance.ActionRefresh {
			if *refreshed {
				return "Kernel rules were already reapplied in this run.", nil
			}
			*refreshed = true
			out, e := m.call(ctx, "kernel-refresh", "")
			return strings.TrimSpace(out), e
		}
		out, e := m.call(ctx, "flows-reset", "", owner.ID)
		return strings.TrimSpace(out), e
	case "haproxy", "realm":
		unit = "gtm-" + owner.ID
	case "gre", "frp", "rathole":
	default:
		return "", errors.New("engine has no maintenance action")
	}
	if !ServiceOK(unit) {
		return "", errors.New("unmanaged service")
	}
	if _, e := os.Stat(filepath.Join(m.UnitDir, unit+".service")); e != nil {
		return "", errors.New("service unit not found")
	}
	verb := "restart"
	if action == maintenance.ActionRefresh {
		if owner.Engine != "haproxy" {
			return "", errors.New("this engine has no non-disruptive refresh")
		}
		verb = "reload"
	}
	out, e := m.Runner.Run(ctx, "systemctl", []string{verb, unit}, "")
	if e != nil {
		return strings.TrimSpace(out), fmt.Errorf("systemctl %s %s failed", verb, unit)
	}
	return fmt.Sprintf("systemctl %s %s", verb, unit), nil
}

func describe(action string, owner maintenance.Owner) string {
	switch {
	case action == maintenance.ActionReboot:
		return "Would reboot the server."
	case owner.Engine == "nftables" || owner.Engine == "iptables":
		if action == maintenance.ActionRefresh {
			return "Would reapply owned kernel rules."
		}
		return "Would clear the tracked flows of this forward."
	case action == maintenance.ActionRefresh:
		return "Would reload the service gracefully."
	}
	return "Would restart the service."
}
