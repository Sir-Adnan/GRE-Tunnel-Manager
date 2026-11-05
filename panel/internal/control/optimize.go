package control

import (
	"context"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Optimization groups, in the order the interface shows them.
var optimizeGroups = []string{"conntrack", "queues", "relay", "routing"}

// Profile levels and goals (see gtm_optimize_catalog).
var (
	optimizeLevels = []string{"conservative", "balanced", "aggressive"}
	optimizeGoals  = []string{"general", "users", "latency"}
)

// Custom values: a catalog-style sysctl key and a value Bash validates fully.
var (
	customKey   = regexp.MustCompile(`^net\.[a-z0-9_.]{1,64}$`)
	customValue = regexp.MustCompile(`^(?:[a-z0-9_]{1,16}|[0-9]{1,10}(?: [0-9]{1,10}){0,2})$`)
)

const maxCustomValues = 40

// OptimizeInput selects groups to preview or apply, or one group ("all"
// for everything) to return to original values. Level and Goal pick the
// profile (empty: the one applied last); Set holds custom values, and
// AllowWorse confirms custom values that are worse than the original.
type OptimizeInput struct {
	Groups     []string          `json:"groups,omitempty"`
	Group      string            `json:"group,omitempty"`
	Level      string            `json:"level,omitempty"`
	Goal       string            `json:"goal,omitempty"`
	Set        map[string]string `json:"set,omitempty"`
	AllowWorse bool              `json:"allow_worse,omitempty"`
}

// OptimizeProfile is an intensity level and a goal.
type OptimizeProfile struct {
	Level string `json:"level"`
	Goal  string `json:"goal"`
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
	// Recommendation of the viewed profile: never worse than the original
	// value. Note is change, same, kept (the original is better), off (the
	// profile leaves the key alone) or missing.
	Recommended string `json:"recommended,omitempty"`
	Reason      string `json:"reason,omitempty"`
	Note        string `json:"note,omitempty"`
}

type OptimizeView struct {
	Memory     uint64   `json:"memory"`
	Flows      *uint64  `json:"flows,omitempty"`
	Congestion []string `json:"congestion"`
	Steps      int      `json:"steps"`
	// Last is when the newest undo step was saved (Unix seconds).
	Last int64 `json:"last,omitempty"`
	// Profile was applied last; View is the profile the keys recommend.
	Profile     OptimizeProfile `json:"profile"`
	View        OptimizeProfile `json:"view"`
	Capped      bool            `json:"capped"`
	File        string          `json:"file"`
	Import      string          `json:"import,omitempty"`
	ServerTools []string        `json:"servertools"`
	Keys        []OptimizeKey   `json:"keys"`
}

// OptimizeChange is one previewed key. Note is change, same, kept, off,
// custom, worse or missing. Kind/Min/Max/Choices bound custom values: kind
// is number, triple (each field, ascending), range (low below high) or choice.
type OptimizeChange struct {
	Group      string   `json:"group"`
	Key        string   `json:"key"`
	Current    string   `json:"current,omitempty"`
	Value      string   `json:"value"`
	Reason     string   `json:"reason"`
	Note       string   `json:"note"`
	OtherFile  string   `json:"other_file,omitempty"`
	OtherValue string   `json:"other_value,omitempty"`
	Kind       string   `json:"kind,omitempty"`
	Min        uint64   `json:"min,omitempty"`
	Max        uint64   `json:"max,omitempty"`
	Choices    []string `json:"choices,omitempty"`
}

type OptimizePlan struct {
	Groups  []string         `json:"groups"`
	Profile OptimizeProfile  `json:"profile"`
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

// profile returns the Bash arguments for the profile: "- -" for the saved one.
func (in OptimizeInput) profile() ([]string, error) {
	if in.Level == "" && in.Goal == "" {
		return []string{"-", "-"}, nil
	}
	if !oneOf(in.Level, optimizeLevels...) || !oneOf(in.Goal, optimizeGoals...) {
		return nil, errors.New("unknown optimization profile")
	}
	return []string{in.Level, in.Goal}, nil
}

// custom returns key=value arguments in a stable order.
func (in OptimizeInput) custom() ([]string, error) {
	if len(in.Set) > maxCustomValues {
		return nil, errors.New("too many custom values")
	}
	out := make([]string, 0, len(in.Set))
	for k, v := range in.Set {
		if !customKey.MatchString(k) || !customValue.MatchString(v) {
			return nil, errors.New("invalid custom value for " + k)
		}
		out = append(out, k+"="+v)
	}
	sort.Strings(out)
	return out, nil
}

func dash(v string) string {
	if v == "-" {
		return ""
	}
	return v
}

func parseProfile(v string) OptimizeProfile {
	f := strings.Fields(v)
	if len(f) != 2 {
		return OptimizeProfile{Level: "balanced", Goal: "general"}
	}
	return OptimizeProfile{Level: f[0], Goal: f[1]}
}

func parseOptimizeStatus(out string) (OptimizeView, error) {
	v := OptimizeView{Congestion: []string{}, ServerTools: []string{}, Keys: []OptimizeKey{}, Profile: parseProfile(""), View: parseProfile("")}
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
			case "last":
				v.Last, _ = strconv.ParseInt(f[2], 10, 64)
			case "profile":
				v.Profile = parseProfile(f[2])
			case "view":
				v.View = parseProfile(f[2])
			case "capped":
				v.Capped = f[2] == "1"
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

// bounds reads gtm_optimize_bounds: "n MIN MAX", "n3 …", "n2 …" or "c A,B".
func (c *OptimizeChange) bounds(spec string) {
	f := strings.Fields(spec)
	switch {
	case len(f) == 2 && f[0] == "c":
		c.Kind, c.Choices = "choice", strings.Split(f[1], ",")
	case len(f) == 3:
		kind := map[string]string{"n": "number", "n2": "range", "n3": "triple"}[f[0]]
		low, e1 := strconv.ParseUint(f[1], 10, 64)
		high, e2 := strconv.ParseUint(f[2], 10, 64)
		if kind != "" && e1 == nil && e2 == nil {
			c.Kind, c.Min, c.Max = kind, low, high
		}
	}
}

func parseOptimizePlan(groups []string, profile OptimizeProfile, out string) OptimizePlan {
	p := OptimizePlan{Groups: groups, Profile: profile, Changes: []OptimizeChange{}}
	for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
		f := strings.Split(line, "\t")
		if (len(f) != 9 && len(f) != 10) || f[0] != "change" {
			continue
		}
		c := OptimizeChange{Group: f[1], Key: f[2], Current: dash(f[3]), Value: f[4], Reason: f[5], Note: f[6], OtherFile: dash(f[7]), OtherValue: dash(f[8])}
		if len(f) == 10 {
			c.bounds(f[9])
		}
		p.Changes = append(p.Changes, c)
	}
	return p
}

// optimize serves the read and change actions through the Bash journal.
func (m *Manager) optimize(ctx context.Context, r Request) (any, error) {
	in := r.Optimize
	switch r.Action {
	case "optimize":
		args := []string{}
		if in.Level != "" || in.Goal != "" {
			p, e := in.profile()
			if e != nil {
				return nil, e
			}
			args = p
		}
		out, e := m.call(ctx, "optimize-status", "", args...)
		if e != nil {
			return nil, e
		}
		return parseOptimizeStatus(out)
	case "optimize-plan", "optimize-apply":
		groups, e := in.groups()
		if e != nil {
			return nil, e
		}
		profile, e := in.profile()
		if e != nil {
			return nil, e
		}
		custom, e := in.custom()
		if e != nil {
			return nil, e
		}
		args := append(profile, strings.Join(groups, ","))
		if r.Action == "optimize-apply" {
			args = append(args, map[bool]string{true: "allow", false: "deny"}[in.AllowWorse])
		}
		out, e := m.call(ctx, r.Action, "", append(args, custom...)...)
		if e != nil || r.Action == "optimize-apply" {
			return out, e
		}
		return parseOptimizePlan(groups, OptimizeProfile{Level: in.Level, Goal: in.Goal}, out), nil
	case "optimize-undo":
		return m.call(ctx, "optimize-undo", "")
	case "optimize-remove":
		if !oneOf(in.Group, append([]string{"all", "previous"}, optimizeGroups...)...) {
			return nil, errors.New("unknown optimization group")
		}
		return m.call(ctx, "optimize-remove", "", in.Group)
	}
	return nil, errors.New("unsupported operation")
}
