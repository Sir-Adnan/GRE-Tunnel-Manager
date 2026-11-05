package control

import (
	"context"
	"encoding/json"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// Watch results.
const (
	WatchActive    = "active"
	WatchUndone    = "undone"
	WatchKept      = "kept"
	WatchCancelled = "cancelled"
	WatchFailed    = "failed"
)

// OptimizeWatch guards one applied step: when a connection that was
// healthy at apply time goes down before Until, the step is undone.
type OptimizeWatch struct {
	Started time.Time `json:"started"`
	Until   time.Time `json:"until"`
	// Step is the saved time (Unix seconds) of the undo step it guards; a
	// later apply or undo replaces the step and cancels the watch.
	Step     int64      `json:"step"`
	Baseline []string   `json:"baseline"`
	Result   string     `json:"result"`
	Ended    *time.Time `json:"ended,omitempty"`
	// Down names the connections whose outage caused the undo.
	Down  []string `json:"down,omitempty"`
	Error string   `json:"error,omitempty"`
}

// watchMinutes are the offered watch windows.
var watchMinutes = []int{5, 10, 15, 30, 60}

type watchState struct {
	mu    sync.Mutex
	watch *OptimizeWatch
}

func (o *Operations) loadWatch() {
	if o.watchPath == "" {
		return
	}
	data, e := os.ReadFile(o.watchPath)
	if e != nil {
		return
	}
	var w OptimizeWatch
	if json.Unmarshal(data, &w) == nil && !w.Started.IsZero() {
		o.watch.watch = &w
	}
}

func (o *Operations) saveWatchLocked() {
	if o.watchPath == "" {
		return
	}
	if o.watch.watch == nil {
		_ = os.Remove(o.watchPath)
		return
	}
	if data, e := json.Marshal(o.watch.watch); e == nil {
		temp := o.watchPath + ".tmp"
		if os.WriteFile(temp, data, 0600) == nil {
			_ = os.Rename(temp, o.watchPath)
		}
	}
}

// startWatch begins guarding the newest step. The baseline holds the
// connections that are up or degraded right now.
func (o *Operations) startWatch(now time.Time, minutes int, step int64) {
	baseline := []string{}
	for owner, s := range o.Health.OwnerStates() {
		if s.Status == health.StatusUp || s.Status == health.StatusDegraded {
			baseline = append(baseline, owner)
		}
	}
	sort.Strings(baseline)
	o.watch.mu.Lock()
	defer o.watch.mu.Unlock()
	o.watch.watch = &OptimizeWatch{Started: now, Until: now.Add(time.Duration(minutes) * time.Minute), Step: step, Baseline: baseline, Result: WatchActive}
	o.saveWatchLocked()
}

// cancelWatch ends an active watch because the operator changed settings.
func (o *Operations) cancelWatch(now time.Time) {
	o.watch.mu.Lock()
	defer o.watch.mu.Unlock()
	if w := o.watch.watch; w != nil && w.Result == WatchActive {
		w.Result, w.Ended = WatchCancelled, &now
		o.saveWatchLocked()
	}
}

// watchView is the active watch or the last result of the past day.
func (o *Operations) watchView(now time.Time) *OptimizeWatch {
	o.watch.mu.Lock()
	defer o.watch.mu.Unlock()
	w := o.watch.watch
	if w == nil || (w.Ended != nil && now.Sub(*w.Ended) > 24*time.Hour) {
		return nil
	}
	c := *w
	return &c
}

func (o *Operations) finishWatch(now time.Time, result, message string, down []string) {
	o.watch.mu.Lock()
	defer o.watch.mu.Unlock()
	if w := o.watch.watch; w != nil && w.Result == WatchActive {
		w.Result, w.Ended, w.Down, w.Error = result, &now, down, truncate(message, 300)
		o.saveWatchLocked()
	}
}

// checkWatch runs after each probe round: an outage of a baseline
// connection that began after the apply undoes the step; reaching Until
// keeps it.
func (o *Operations) checkWatch(ctx context.Context, m *Manager, lock sync.Locker) {
	w := o.watchView(time.Now().UTC())
	if w == nil || w.Result != WatchActive {
		return
	}
	now := time.Now().UTC()
	states := o.Health.OwnerStates()
	down := []string{}
	for _, owner := range w.Baseline {
		if s, ok := states[owner]; ok && s.Status == health.StatusDown && s.Since.After(w.Started) {
			name := s.Name
			if name == "" {
				name = owner
			}
			down = append(down, name)
		}
	}
	if len(down) == 0 {
		if now.After(w.Until) {
			o.finishWatch(now, WatchKept, "", nil)
			o.Notify.Emit(notify.Event{Time: now, Kind: notify.KindOptimizeKept, Detail: "watched for " + shortDuration(w.Until.Sub(w.Started))})
		}
		return
	}
	step, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	lock.Lock()
	out, e := m.call(step, "optimize-status", "")
	if e == nil {
		view, parseError := parseOptimizeStatus(out)
		if parseError != nil || view.Last != w.Step {
			lock.Unlock()
			o.finishWatch(now, WatchCancelled, "the guarded step is no longer the newest", down)
			return
		}
		out, e = m.call(step, "optimize-undo", "")
	}
	lock.Unlock()
	o.invalidate()
	_ = audit(Request{Action: "optimize-rollback"}, e)
	detail := strings.Join(down, ", ")
	if e != nil {
		o.finishWatch(now, WatchFailed, e.Error(), down)
		o.Notify.Emit(notify.Event{Time: now, Kind: notify.KindRollback, Severity: notify.SeverityCritical, Detail: "undo failed: " + truncate(e.Error(), 120) + " · " + detail})
		return
	}
	o.finishWatch(now, WatchUndone, strings.TrimSpace(out), down)
	o.Notify.Emit(notify.Event{Time: now, Kind: notify.KindRollback, Detail: "down after apply: " + detail})
}
