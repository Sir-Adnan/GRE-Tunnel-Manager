package nodes

import (
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

const (
	nodeA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	nodeB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func presenceHub(start time.Time) (*Hub, *time.Time) {
	now := start
	h := &Hub{cache: map[string]observation{}, now: func() time.Time { return now }}
	h.state.Nodes = []Node{{ID: nodeA, Name: "Exit A"}, {ID: nodeB, Name: "Exit B"}}
	return h, &now
}

func TestPresenceReportsEachChangeOnce(t *testing.T) {
	start := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	h, now := presenceHub(start)
	last := map[string]presence{}

	// Nodes that never reported are not watched.
	changes, last := h.presenceChanges(last)
	if len(changes) != 0 || len(last) != 0 {
		t.Fatalf("waiting nodes reported: %+v %+v", changes, last)
	}
	h.cache[nodeA] = observation{seen: start}
	h.cache[nodeB] = observation{seen: start, report: Report{Failure: &Problem{Code: "broker"}}}
	if changes, last = h.presenceChanges(last); len(changes) != 0 || len(last) != 2 {
		t.Fatalf("first sight must be quiet: %+v %+v", changes, last)
	}

	// A stays silent past the limit; B keeps reporting (degraded is reachable).
	*now = start.Add(4 * time.Minute)
	h.cache[nodeB] = observation{seen: *now}
	changes, last = h.presenceChanges(last)
	if len(changes) != 1 || changes[0] != (control.NodeChange{ID: nodeA, Name: "Exit A", Online: false, Seconds: 240}) {
		t.Fatalf("offline change: %+v", changes)
	}
	*now = start.Add(5 * time.Minute)
	if changes, last = h.presenceChanges(last); len(changes) != 0 {
		t.Fatalf("offline repeated: %+v", changes)
	}

	// A reports again: one change with the outage measured from its last report.
	*now = start.Add(10 * time.Minute)
	h.cache[nodeA] = observation{seen: *now}
	h.cache[nodeB] = observation{seen: *now}
	changes, last = h.presenceChanges(last)
	if len(changes) != 1 || !changes[0].Online || changes[0].Seconds != 600 {
		t.Fatalf("online change: %+v", changes)
	}

	// A revoked node is forgotten without a message.
	h.state.Nodes[1].Revoked = true
	if changes, last = h.presenceChanges(last); len(changes) != 0 || len(last) != 1 {
		t.Fatalf("revoked node: %+v %+v", changes, last)
	}
}

func TestPresenceAfterRestartWaitsForOnline(t *testing.T) {
	start := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	h, now := presenceHub(start)
	h.cache[nodeA] = observation{seen: start.Add(-time.Hour)}
	changes, last := h.presenceChanges(map[string]presence{})
	if len(changes) != 0 || len(last) != 0 {
		t.Fatalf("a node offline at start must stay quiet: %+v %+v", changes, last)
	}
	*now = start.Add(time.Minute)
	h.cache[nodeA] = observation{seen: *now}
	if changes, _ = h.presenceChanges(last); len(changes) != 0 {
		t.Fatalf("first online sight is not a recovery: %+v", changes)
	}
}
