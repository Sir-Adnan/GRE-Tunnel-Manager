package control

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/maintenance"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// monitorHealth probes on the configured interval, and destinations of
// forwards with failover on their shorter interval. While monitoring is off
// it only reads one in-memory setting per second; turning it off restores
// every excluded destination.
func (b *Broker) monitorHealth(ctx context.Context, done <-chan struct{}) {
	ops := b.Manager.Ops
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() { _ = ops.Health.Flush(time.Now().UTC(), true) }()
	full, fast := 1<<30, 1<<30
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
		}
		s := ops.Health.Settings()
		if !s.Enabled {
			ops.cancelWatch(time.Now().UTC())
			if full != 1<<30 {
				// Restore exclusions once; monitoring can no longer see recovery.
				ops.restoreFailover(ctx, b.Manager, &b.mu)
			}
			full, fast = 1<<30, 1<<30
			continue
		}
		full++
		fast++
		runFull, runFast := full >= s.Interval, len(s.Failover) > 0 && fast >= s.FailoverInterval
		if !runFull && !runFast {
			continue
		}
		fast = 0
		if runFull {
			full = 0
		}
		limit := 4 * time.Second
		if runFull {
			limit = time.Duration(min(s.Interval-1, 20)) * time.Second
		}
		round, cancel := context.WithTimeout(ctx, limit)
		inventory, e := ops.healthRound(round, b.Manager, time.Now().UTC(), runFull)
		cancel()
		if e != nil && !errors.Is(e, context.Canceled) {
			log.Printf("health round incomplete: %v", e)
		}
		if e == nil {
			ops.runFailover(ctx, b.Manager, inventory, &b.mu)
			if runFull {
				ops.checkWatch(ctx, b.Manager, &b.mu)
			}
		}
	}
}

// runMaintenance evaluates plans every five seconds and executes due runs one
// at a time. Each step takes the mutation lock only for its own command.
func (b *Broker) runMaintenance(ctx context.Context, done <-chan struct{}) {
	ops := b.Manager.Ops
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
		}
		env := opsEnv{ctx: ctx, o: ops, m: b.Manager}
		for _, run := range ops.Maintenance.Evaluate(time.Now().UTC(), env) {
			b.executeRun(ctx, run)
		}
	}
}

func (b *Broker) executeRun(ctx context.Context, run maintenance.Run) {
	ops := b.Manager.Ops
	entries := []maintenance.Entry{}
	var failure error
	if run.Plan.Action == maintenance.ActionReboot {
		now := time.Now().UTC()
		entry := maintenance.Entry{Reason: run.Reason, Started: now, Ended: now, Result: maintenance.ResultRebooting, Message: "Reboot requested. " + run.Detail}
		if run.Plan.DryRun {
			entry.Result, entry.Message = maintenance.ResultDryRun, describe(run.Plan.Action, maintenance.Owner{})
		}
		// Persist before rebooting so the next start can confirm the restart.
		if e := ops.Maintenance.Finish(run, []maintenance.Entry{entry}); e != nil || run.Plan.DryRun {
			return
		}
		b.mu.Lock()
		out, e := b.Manager.Runner.Run(ctx, "systemctl", []string{"reboot"}, "")
		b.mu.Unlock()
		_ = audit(Request{Action: "maintenance-reboot"}, e)
		if e != nil {
			at := time.Now().UTC()
			_ = ops.Maintenance.Finish(run, []maintenance.Entry{{Reason: run.Reason, Started: at, Ended: at, Result: maintenance.ResultFailed, Message: "Reboot request failed: " + out}})
		}
		return
	}
	refreshed := false
	for i, owner := range run.Owners {
		if i > 0 && run.Plan.Guards.Stagger > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Duration(run.Plan.Guards.Stagger) * time.Second):
			}
		}
		started := time.Now().UTC()
		entry := maintenance.Entry{Owner: owner.ID, OwnerName: owner.Name, Engine: owner.Engine, Reason: run.Reason, Started: started}
		if run.Plan.DryRun {
			entry.Result, entry.Message, entry.Ended = maintenance.ResultDryRun, describe(run.Plan.Action, owner), started
			entries = append(entries, entry)
			continue
		}
		step, cancel := context.WithTimeout(ctx, 2*time.Minute)
		b.mu.Lock()
		message, e := b.Manager.maintain(step, run.Plan.Action, owner, &refreshed)
		b.mu.Unlock()
		cancel()
		entry.Ended, entry.Result, entry.Message = time.Now().UTC(), maintenance.ResultOK, truncate(message, 300)
		if e != nil {
			entry.Result, failure = maintenance.ResultFailed, e
			entry.Message = truncate(e.Error()+" "+message, 300)
		}
		entries = append(entries, entry)
	}
	ops.invalidate()
	if e := ops.Maintenance.Finish(run, entries); e != nil {
		log.Printf("maintenance history write failed: %v", e)
	}
	if !run.Plan.DryRun && ops.Notify != nil && len(entries) > 0 {
		kind, detail := notify.KindMaintenance, describe(run.Plan.Action, run.Owners[0])
		if failure != nil {
			kind, detail = notify.KindMaintenanceFailed, truncate(failure.Error(), 200)
		}
		ops.Notify.Emit(notify.Event{Kind: kind, Name: run.Plan.Name, Detail: fmt.Sprintf("%s (%d)", detail, len(entries))})
	}
	if !run.Plan.DryRun {
		_ = audit(Request{Action: "maintenance-" + run.Plan.Action}, failure)
	}
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// runSnapshots checks the backup schedule every 30 seconds; a due snapshot
// runs under the mutation lock like any other change.
func (b *Broker) runSnapshots(ctx context.Context, done <-chan struct{}) {
	ops := b.Manager.Ops
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-done:
			return
		case <-ticker.C:
		}
		if !ops.Snapshots.Due(time.Now().UTC(), ops.Maintenance.Location()) {
			continue
		}
		step, cancel := context.WithTimeout(ctx, 5*time.Minute)
		b.mu.Lock()
		_, e := b.Manager.createSnapshot(step, true)
		b.mu.Unlock()
		cancel()
		_ = audit(Request{Action: "snapshots-scheduled"}, e)
	}
}
