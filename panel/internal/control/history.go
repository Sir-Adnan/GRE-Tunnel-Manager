package control

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// HistoryInput selects a restore point; Revision guards the restore.
type HistoryInput struct {
	Point    string `json:"point,omitempty"`
	Revision string `json:"revision,omitempty"`
}

// HistoryChange is one connection that differs between two states. Kind is
// added, removed or changed; Fields names what changed.
type HistoryChange struct {
	ID     string   `json:"id"`
	Name   string   `json:"name"`
	Engine string   `json:"engine"`
	Kind   string   `json:"kind"`
	Fields []string `json:"fields,omitempty"`
}

// HistoryEntry is one forwarding change: Point holds the state from before
// it, so restoring Point undoes this change and every later one.
type HistoryEntry struct {
	Point   string          `json:"point"`
	Time    time.Time       `json:"time"`
	Count   int             `json:"count"`
	Changes []HistoryChange `json:"changes"`
	Invalid bool            `json:"invalid,omitempty"`
}

type HistoryView struct {
	Revision string         `json:"revision"`
	Total    int            `json:"total"`
	Entries  []HistoryEntry `json:"entries"`
}

// HistoryReview is what restoring Point would change now.
type HistoryReview struct {
	Point    string          `json:"point"`
	Time     time.Time       `json:"time"`
	Revision string          `json:"revision"`
	Count    int             `json:"count"`
	Changes  []HistoryChange `json:"changes"`
}

var pointName = regexp.MustCompile(`^([0-9]{8}T[0-9]{6})-[0-9]+-[0-9]+\.tsv$`)

func pointTime(name string) time.Time {
	m := pointName.FindStringSubmatch(name)
	if m == nil {
		return time.Time{}
	}
	t, _ := time.Parse("20060102T150405", m[1])
	return t.UTC()
}

type historyPoint struct {
	name        string
	connections []model.Connection
	invalid     bool
}

type historyData struct {
	revision string
	total    int
	points   []historyPoint
}

func parseHistory(out string) (historyData, error) {
	var d historyData
	var rows []string
	flush := func() error {
		if len(d.points) == 0 || d.points[len(d.points)-1].invalid {
			return nil
		}
		connections, _, e := model.ParseState(strings.Join(rows, "\n"))
		if e != nil {
			d.points[len(d.points)-1].invalid = true
			return nil
		}
		d.points[len(d.points)-1].connections = connections
		return nil
	}
	for _, line := range strings.Split(strings.TrimRight(out, "\n"), "\n") {
		kind, rest, _ := strings.Cut(line, "\t")
		switch kind {
		case "revision":
			d.revision = rest
		case "total":
			fmt.Sscanf(rest, "%d", &d.total)
		case "point", "invalid":
			_ = flush()
			rows = nil
			d.points = append(d.points, historyPoint{name: rest, invalid: kind == "invalid"})
		case "row":
			rows = append(rows, rest)
		}
	}
	_ = flush()
	if len(d.revision) != 64 {
		return d, errors.New("unexpected history output")
	}
	return d, nil
}

func targetsText(c model.Connection) string {
	parts := make([]string, len(c.Targets))
	for i, t := range c.Targets {
		parts[i] = fmt.Sprintf("%s:%d@%d", t.IP, t.Port, t.Weight)
	}
	return strings.Join(parts, ",")
}

func optionsText(c model.Connection) string {
	keys := make([]string, 0, len(c.Options))
	for k, v := range c.Options {
		keys = append(keys, k+"="+v)
	}
	sort.Strings(keys)
	return strings.Join(keys, ";")
}

// diffConnections lists what changes from before to after.
func diffConnections(before, after []model.Connection) []HistoryChange {
	old := map[string]model.Connection{}
	for _, c := range before {
		old[c.ID] = c
	}
	out := []HistoryChange{}
	seen := map[string]bool{}
	for _, c := range after {
		seen[c.ID] = true
		p, ok := old[c.ID]
		if !ok {
			out = append(out, HistoryChange{ID: c.ID, Name: c.Name, Engine: c.Engine, Kind: "added"})
			continue
		}
		fields := []string{}
		check := func(field string, a, b any) {
			if fmt.Sprint(a) != fmt.Sprint(b) {
				fields = append(fields, field)
			}
		}
		check("name", p.Name, c.Name)
		check("enabled", p.Enabled, c.Enabled)
		check("engine", p.Engine, c.Engine)
		check("listen", p.Bind+" "+p.Ports, c.Bind+" "+c.Ports)
		check("protocol", p.Protocol, c.Protocol)
		check("destinations", targetsText(p), targetsText(c))
		check("strategy", p.Strategy, c.Strategy)
		check("routing", p.SNAT+" "+p.Interface, c.SNAT+" "+c.Interface)
		check("options", optionsText(p), optionsText(c))
		if len(fields) > 0 {
			out = append(out, HistoryChange{ID: c.ID, Name: c.Name, Engine: c.Engine, Kind: "changed", Fields: fields})
		}
	}
	for _, c := range before {
		if !seen[c.ID] {
			out = append(out, HistoryChange{ID: c.ID, Name: c.Name, Engine: c.Engine, Kind: "removed"})
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (m *Manager) history(ctx context.Context, r Request) (any, error) {
	in := r.History
	if r.Action == "history-restore" {
		if !pointName.MatchString(in.Point) || !digestValid(in.Revision) {
			return nil, errors.New("invalid restore point; review it again")
		}
		return m.call(ctx, "history-restore", "", in.Point, in.Revision)
	}
	out, e := m.call(ctx, "history", "")
	if e != nil {
		return nil, e
	}
	d, e := parseHistory(out)
	if e != nil {
		return nil, e
	}
	current, _, e := m.state(ctx)
	if e != nil {
		return nil, e
	}
	if r.Action == "history-review" {
		return reviewPoint(d, current, in.Point)
	}
	return historyView(d, current), nil
}

// historyView pairs each point with the state after it: the next newer
// point, or the current state for the newest.
func historyView(d historyData, current []model.Connection) HistoryView {
	v := HistoryView{Revision: d.revision, Total: d.total, Entries: []HistoryEntry{}}
	after := current
	for _, p := range d.points {
		e := HistoryEntry{Point: p.name, Time: pointTime(p.name), Count: len(p.connections), Changes: []HistoryChange{}, Invalid: p.invalid}
		if !p.invalid {
			e.Changes = diffConnections(p.connections, after)
			after = p.connections
		}
		v.Entries = append(v.Entries, e)
	}
	return v
}

func reviewPoint(d historyData, current []model.Connection, name string) (HistoryReview, error) {
	i := slices.IndexFunc(d.points, func(p historyPoint) bool { return p.name == name })
	if i < 0 || d.points[i].invalid {
		return HistoryReview{}, errors.New("restore point not found")
	}
	p := d.points[i]
	return HistoryReview{Point: p.name, Time: pointTime(p.name), Revision: d.revision, Count: len(p.connections), Changes: diffConnections(current, p.connections)}, nil
}
