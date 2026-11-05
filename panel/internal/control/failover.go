package control

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// FailoverStatus is one kernel forward's health failover state.
type FailoverStatus struct {
	// Excluded are the 1-based destinations that receive no new flows.
	Excluded []int     `json:"excluded"`
	Changed  time.Time `json:"changed,omitzero"`
	Message  string    `json:"message,omitempty"`
	Error    string    `json:"error,omitempty"`
}

// failoverRetry spaces attempts after a failed exclusion change.
const failoverRetry = time.Minute

// failover remembers what was applied, so a change runs only on a status
// transition. The kernel side is runtime-only (cleared at boot).
type failover struct {
	mu      sync.Mutex
	loaded  bool
	applied map[string]string // forward → "signature|list"
	failed  map[string]time.Time
	status  map[string]FailoverStatus
}

// excludeFunc runs the allowlisted Bash forward-exclude operation.
type excludeFunc func(ctx context.Context, id, list string) (string, error)

func failoverEligible(engine string, enabled bool, destinations int) bool {
	return (engine == "nftables" || engine == "iptables") && enabled && destinations > 1
}

// signature identifies a destination list; an edit invalidates exclusions.
func signature(c inventoryConnection) string { return strings.Join(c.targets, ",") }

type inventoryConnection struct {
	id      string
	targets []string
}

func connectionsOf(inventory Inventory) map[string]inventoryConnection {
	out := map[string]inventoryConnection{}
	for _, c := range inventory.Connections {
		if !failoverEligible(c.Engine, c.Enabled, len(effectiveTargets(c))) {
			continue
		}
		ic := inventoryConnection{id: c.ID}
		for _, t := range effectiveTargets(c) {
			ic.targets = append(ic.targets, t.IP+"/"+strconv.Itoa(t.Port)+"@"+strconv.Itoa(t.Weight))
		}
		out[c.ID] = ic
	}
	return out
}

// desiredExclusions lists, per eligible forward, the destinations whose
// probe is down. Every destination down (or none) means no exclusion: the
// kernel keeps the full list rather than dropping all traffic.
func desiredExclusions(settings health.Settings, inventory Inventory, statuses map[string]string) map[string]string {
	selected := settings.FailoverSet()
	targets := healthTargets(inventory)
	connections := connectionsOf(inventory)
	out := map[string]string{}
	for id, c := range connections {
		list := "-"
		if settings.Enabled && selected[id] {
			down := map[int]bool{}
			for _, t := range targets {
				if t.Owner == id && t.Kind != health.KindService && statuses[t.Key] == health.StatusDown {
					for _, index := range t.Indexes {
						down[index] = true
					}
				}
			}
			if n := len(down); n > 0 && n < len(c.targets) {
				indexes := make([]int, 0, n)
				for index := range down {
					indexes = append(indexes, index)
				}
				sort.Ints(indexes)
				parts := make([]string, len(indexes))
				for i, index := range indexes {
					parts[i] = strconv.Itoa(index)
				}
				list = strings.Join(parts, ",")
			}
		}
		out[id] = list
	}
	return out
}

// readExclusions loads the runtime file the Bash helper keeps, so a broker
// restart without a reboot knows what the kernel already excludes.
func readExclusions(path string) map[string]bool {
	out := map[string]bool{}
	f, e := os.Open(path)
	if e != nil {
		return out
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if fields := strings.Split(scanner.Text(), "\t"); len(fields) == 3 {
			out[fields[0]] = true
		}
	}
	return out
}

func parseList(list string) []int {
	out := []int{}
	if list == "-" {
		return out
	}
	for _, part := range strings.Split(list, ",") {
		if n, e := strconv.Atoi(part); e == nil {
			out = append(out, n)
		}
	}
	return out
}

// reconcile applies changed exclusions. Unknown state (first round after a
// restart) re-sends the desired list for forwards the runtime file names.
func (f *failover) reconcile(ctx context.Context, now time.Time, file string, want map[string]string, connections map[string]inventoryConnection, exclude excludeFunc) {
	f.mu.Lock()
	if !f.loaded {
		f.loaded, f.applied, f.failed, f.status = true, map[string]string{}, map[string]time.Time{}, map[string]FailoverStatus{}
		present := readExclusions(file)
		for id, c := range connections {
			if !present[id] {
				f.applied[id] = signature(c) + "|-"
			}
		}
	}
	type change struct{ id, list, key string }
	changes := []change{}
	for id, list := range want {
		key := signature(connections[id]) + "|" + list
		if f.applied[id] == key || now.Sub(f.failed[id]) < failoverRetry {
			continue
		}
		changes = append(changes, change{id, list, key})
	}
	for id := range f.status {
		if _, ok := want[id]; !ok {
			delete(f.status, id)
			delete(f.applied, id)
		}
	}
	f.mu.Unlock()
	sort.Slice(changes, func(i, j int) bool { return changes[i].id < changes[j].id })
	for _, c := range changes {
		out, e := exclude(ctx, c.id, c.list)
		f.mu.Lock()
		if e != nil {
			// Keep the last applied state; show why the change did not land.
			status := f.status[c.id]
			status.Error = truncate(e.Error(), 300)
			f.status[c.id] = status
			f.failed[c.id] = now
		} else {
			f.status[c.id] = FailoverStatus{Excluded: parseList(c.list), Changed: now, Message: truncate(strings.TrimSpace(out), 300)}
			f.applied[c.id] = c.key
			delete(f.failed, c.id)
		}
		f.mu.Unlock()
		_ = audit(Request{Action: "health-failover"}, e)
	}
}

// view reports forwards with an active exclusion or a recent change.
func (f *failover) view() map[string]FailoverStatus {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]FailoverStatus, len(f.status))
	for id, s := range f.status {
		out[id] = s
	}
	return out
}

// runFailover is called after every probe round of the real broker.
func (o *Operations) runFailover(ctx context.Context, m *Manager, inventory Inventory, lock sync.Locker) {
	want := desiredExclusions(o.Health.Settings(), inventory, o.Health.Statuses())
	names := map[string]string{}
	for _, c := range inventory.Connections {
		names[c.ID] = c.Name
	}
	o.failover.reconcile(ctx, time.Now().UTC(), filepath.Join(o.runDir, "excluded.tsv"), want, connectionsOf(inventory), func(ctx context.Context, id, list string) (string, error) {
		lock.Lock()
		step, cancel := context.WithTimeout(ctx, time.Minute)
		out, e := m.call(step, "forward-exclude", "", id, list)
		cancel()
		lock.Unlock()
		if e == nil && o.Notify != nil {
			excluded := ""
			if list != "-" {
				excluded = strings.ReplaceAll(list, ",", ", ")
			}
			o.Notify.Emit(notify.Event{Kind: notify.KindFailover, Owner: id, Name: names[id], Detail: failoverDetail(list), Args: map[string]string{"excluded": excluded}})
		}
		return out, e
	})
}

// restoreFailover clears every exclusion after monitoring is turned off.
func (o *Operations) restoreFailover(ctx context.Context, m *Manager, lock sync.Locker) {
	inventory, e := o.cachedInventory(ctx, m, 30*time.Second)
	if e != nil {
		return
	}
	o.runFailover(ctx, m, inventory, lock)
}
