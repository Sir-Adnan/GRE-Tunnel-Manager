package nodes

import (
	"context"
	"log"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

// offlineAfter is how long a Node may stay silent before it counts as offline.
// Agents report about once a minute.
const offlineAfter = 3 * time.Minute

// presenceEvery is how often the Controller compares Node states. It reads
// the in-memory reports only; watching adds no network traffic.
const presenceEvery = 30 * time.Second

// reportStatus is a reporting Node's state: online, degraded (it reported a
// failure) or offline (no report for offlineAfter).
func (h *Hub) reportStatus(o observation) string {
	switch {
	case h.now().Sub(o.seen) > offlineAfter:
		return "offline"
	case o.report.Failure != nil:
		return "degraded"
	}
	return "online"
}

// presence is what the watcher remembers about one Node.
type presence struct {
	online bool
	// since is when the Node was last seen (offline) or came back (online).
	since time.Time
}

// reporting is one Node that has reported since the panel started.
type reporting struct {
	name   string
	online bool
	seen   time.Time
}

// presenceNow lists the reporting, non-revoked Nodes with their state.
func (h *Hub) presenceNow() map[string]reporting {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := map[string]reporting{}
	for _, n := range h.state.Nodes {
		o, ok := h.cache[n.ID]
		if !ok || n.Revoked {
			continue
		}
		out[n.ID] = reporting{n.Name, h.reportStatus(o) != "offline", o.seen}
	}
	return out
}

// presenceChanges compares the current Node states with the remembered ones.
// A Node is reported only after the watcher saw it online, so a panel restart
// while a Node is down stays quiet until it returns. Removed or revoked Nodes
// are forgotten without a message.
func (h *Hub) presenceChanges(last map[string]presence) ([]control.NodeChange, map[string]presence) {
	now := h.now()
	next := map[string]presence{}
	var changes []control.NodeChange
	for id, n := range h.presenceNow() {
		before, known := last[id]
		switch {
		case !known:
			if n.online {
				next[id] = presence{online: true, since: now}
			}
			continue
		case before.online && !n.online:
			next[id] = presence{online: false, since: n.seen}
			changes = append(changes, control.NodeChange{ID: id, Name: n.name, Online: false, Seconds: int64(now.Sub(n.seen).Seconds())})
		case !before.online && n.online:
			next[id] = presence{online: true, since: now}
			changes = append(changes, control.NodeChange{ID: id, Name: n.name, Online: true, Seconds: int64(now.Sub(before.since).Seconds())})
		default:
			next[id] = before
		}
	}
	return changes, next
}

// WatchPresence tells the broker when a Node stops reporting or comes back;
// the broker turns each change into a notification.
func (h *Hub) WatchPresence(ctx context.Context, client control.Client) {
	ticker := time.NewTicker(presenceEvery)
	defer ticker.Stop()
	last := map[string]presence{}
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		changes, next := h.presenceChanges(last)
		last = next
		for _, change := range changes {
			c, cancel := context.WithTimeout(ctx, 15*time.Second)
			_, e := client.Do(c, control.Request{Action: "notifications-node", Notify: control.NotifyInput{Node: &change}})
			cancel()
			if e != nil {
				log.Printf("node presence notification failed: %v", e)
			}
		}
	}
}
