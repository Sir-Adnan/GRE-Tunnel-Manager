package control

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/maintenance"
)

// monitorHealth probes on the configured interval. While monitoring is off it
// only reads one in-memory setting per second.
func (b *Broker) monitorHealth(ctx context.Context, done <-chan struct{}) {
	ops := b.Manager.Ops
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	defer func() { _ = ops.Health.Flush(time.Now().UTC(), true) }()
	elapsed := 1 << 30
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
			elapsed = 1 << 30
			continue
		}
		if elapsed++; elapsed < s.Interval {
			continue
		}
		elapsed = 0
		round, cancel := context.WithTimeout(ctx, time.Duration(min(s.Interval-1, 20))*time.Second)
		if e := ops.healthRound(round, b.Manager, time.Now().UTC()); e != nil && !errors.Is(e, context.Canceled) {
			log.Printf("health round incomplete: %v", e)
		}
		cancel()
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
