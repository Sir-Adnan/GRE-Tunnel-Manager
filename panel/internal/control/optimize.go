package control

import (
	"context"
	"errors"
	"strconv"
	"strings"
)

// Optimization groups, in the order the interface shows them.
var optimizeGroups = []string{"conntrack", "queues", "relay", "routing"}

// OptimizeInput selects groups to preview or apply, or one group ("all"
// for everything) to return to original values.
type OptimizeInput struct {
	Groups []string `json:"groups,omitempty"`
	Group  string   `json:"group,omitempty"`
}

// OptimizeKey is one catalog sysctl: its live value, the value from before
// the panel first changed it and what the panel applied ("" when the panel
// does not manage it), plus the last other drop-in that also sets it.
// The panel's drop-in sorts after other files, so its value wins at boot.
type OptimizeKey struct {
	Group        string `json:"group"`
	Key          string `json:"key"`
	Current      string `json:"current"`
	Before       string `json:"before,omitempty"`
	Applied      string `json:"applied,omitempty"`
	AppliedGroup string `json:"applied_group,omitempty"`
	OtherFile    string `json:"other_file,omitempty"`
	OtherValue   string `json:"other_value,omitempty"`
	// Recommendation for this server: never worse than the live value.
	// Note is change, same, kept (the live value is better) or missing.
	Recommended string `json:"recommended,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Note        string `json:"note,omitempty"`
}

type OptimizeView struct {
	Memory      uint64        `json:"memory"`
	Flows       *uint64       `json:"flows,omitempty"`
	Congestion  []string      `json:"congestion"`
	Steps       int           `json:"steps"`
	File        string        `json:"file"`
	Import      string        `json:"import,omitempty"`
	ServerTools []string      `json:"servertools"`
	Keys        []OptimizeKey `json:"keys"`
}

// OptimizeChange is one previewed key. Note is change, same, kept or missing.
type OptimizeChange struct {
	Group      string `json:"group"`
	Key        string `json:"key"`
	Current    string `json:"current,omitempty"`
	Value      string `json:"value"`
	Reason     string `json:"reason"`
	Note       string `json:"note"`
	OtherFile  string `json:"other_file,omitempty"`
	OtherValue string `json:"other_value,omitempty"`
}

type OptimizePlan struct {
	Groups  []string         `json:"groups"`
	Changes []OptimizeChange `json:"changes"`
}

// groups validates and orders a group selection.
func (in OptimizeInput) groups() ([]string, error) {
	seen := map[string]bool{}
	for _, g := range in.Groups {
		if !oneOf(g, optimizeGroups...) || seen[g] {
			return nil, errors.New("unknown optimization group")
		}
		seen[g] = true
	}
	out := []string{}
	for _, g := range optimizeGroups {
		if seen[g] {
			out = append(out, g)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("choose at least one optimization group")
	}
	return out, nil
}

func dash(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

func parseOptimizeStatus(out string) (OptimizeView, error) {
	v := OptimizeView{Congestion: []string{}, ServerTools: []string{}, Keys: []OptimizeKey{}}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		switch {
		case len(f) == 3 && f[0] == "meta":
			switch f[1] {
			case "memory":
				v.Memory, _ = strconv.ParseUint(f[2], 10, 64)
			case "flows":
				if n, e := strconv.ParseUint(f[2], 10, 64); e == nil {
					v.Flows = &n
				}
			case "congestion":
				if f[2] != "-" {
					v.Congestion = strings.Fields(f[2])
				}
			case "steps":
				v.Steps, _ = strconv.Atoi(f[2])
			case "file":
				v.File = f[2]
			case "import":
				v.Import = f[2]
			case "servertools":
				v.ServerTools = append(v.ServerTools, f[2])
			}
		case len(f) == 12 && f[0] == "key":
			v.Keys = append(v.Keys, OptimizeKey{Group: f[1], Key: f[2], Current: dash(f[3]), Before: dash(f[4]), Applied: dash(f[5]), AppliedGroup: dash(f[6]), OtherFile: dash(f[7]), OtherValue: dash(f[8]), Recommended: dash(f[9]), Reason: dash(f[10]), Note: dash(f[11])})
		}
	}
	if v.File == "" {
		return v, errors.New("unexpected optimization status")
	}
	return v, nil
}

func parseOptimizePlan(groups []string, out string) OptimizePlan {
	p := OptimizePlan{Groups: groups, Changes: []OptimizeChange{}}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		if f := strings.Split(line, "\t"); len(f) == 9 && f[0] == "change" {
			p.Changes = append(p.Changes, OptimizeChange{Group: f[1], Key: f[2], Current: dash(f[3]), Value: f[4], Reason: f[5], Note: f[6], OtherFile: dash(f[7]), OtherValue: dash(f[8])})
		}
	}
	return p
}

// optimize serves the read and change actions through the Bash journal.
func (m *Manager) optimize(ctx context.Context, r Request) (any, error) {
	switch r.Action {
	case "optimize":
		out, e := m.call(ctx, "optimize-status", "")
		if e != nil {
			return nil, e
		}
		return parseOptimizeStatus(out)
	case "optimize-plan", "optimize-apply":
		groups, e := r.Optimize.groups()
		if e != nil {
			return nil, e
		}
		out, e := m.call(ctx, r.Action, "", groups...)
		if e != nil || r.Action == "optimize-apply" {
			return out, e
		}
		return parseOptimizePlan(groups, out), nil
	case "optimize-undo":
		return m.call(ctx, "optimize-undo", "")
	case "optimize-remove":
		if !oneOf(r.Optimize.Group, append([]string{"all", "previous"}, optimizeGroups...)...) {
			return nil, errors.New("unknown optimization group")
		}
		return m.call(ctx, "optimize-remove", "", r.Optimize.Group)
	}
	return nil, errors.New("unsupported operation")
}
