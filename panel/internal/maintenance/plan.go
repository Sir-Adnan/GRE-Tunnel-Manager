// Package maintenance decides when scheduled or health-triggered maintenance
// runs. It is pure scheduling: it never executes commands. The broker asks
// Evaluate for due runs, performs the allowlisted actions and reports back.
package maintenance

import (
	"errors"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	// ActionRefresh never disconnects: kernel rules are reapplied and HAProxy
	// reloads gracefully.
	ActionRefresh = "refresh"
	// ActionRestart restarts a service or GRE link, or clears the tracked flows
	// of a kernel forward. Its users reconnect.
	ActionRestart = "restart"
	ActionReboot  = "reboot"

	TriggerInterval = "interval"
	TriggerDaily    = "daily"
	TriggerWeekly   = "weekly"
	TriggerUptime   = "uptime"
	TriggerHealth   = "health"

	ConditionDown    = "down"
	ConditionLatency = "latency"

	MaxPlans = 32
)

type Trigger struct {
	Kind       string   `json:"kind"`
	Hours      int      `json:"hours,omitempty"`
	Times      []string `json:"times,omitempty"`
	Days       []int    `json:"days,omitempty"`
	UptimeDays int      `json:"uptime_days,omitempty"`
	Condition  string   `json:"condition,omitempty"`
	Minutes    int      `json:"minutes,omitempty"`
	LatencyMs  int      `json:"latency_ms,omitempty"`
}

type Guards struct {
	// Window limits interval and health triggers to "HH:MM-HH:MM" local time.
	Window string `json:"window,omitempty"`
	// QuietMbps waits until host throughput falls below this rate.
	QuietMbps float64 `json:"quiet_mbps,omitempty"`
	// QuietWait is how many minutes to wait for quiet traffic.
	QuietWait int `json:"quiet_wait,omitempty"`
	// QuietTimeout is "run" or "skip" when the wait ends without quiet traffic.
	QuietTimeout string `json:"quiet_timeout,omitempty"`
	Cooldown     int    `json:"cooldown"`
	MaxPerDay    int    `json:"max_per_day"`
	// MinUptime refuses reboots this many minutes after boot (loop guard).
	MinUptime int `json:"min_uptime,omitempty"`
	// Notice is a cancellable countdown in minutes before a run starts.
	Notice int `json:"notice,omitempty"`
	// Stagger waits this many seconds between owners of one run.
	Stagger int `json:"stagger,omitempty"`
}

type Plan struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Enabled bool      `json:"enabled"`
	Action  string    `json:"action"`
	Scope   []string  `json:"scope"`
	Trigger Trigger   `json:"trigger"`
	Guards  Guards    `json:"guards"`
	DryRun  bool      `json:"dry_run"`
	Created time.Time `json:"created,omitzero"`
}

// Owner is one connection or resource a plan can act on.
type Owner struct {
	ID     string `json:"id"`
	Name   string `json:"name"`
	Engine string `json:"engine"`
}

// Applies reports whether action is meaningful for an engine. Refresh is
// limited to engines with a non-disruptive path.
func Applies(action, engine string) bool {
	switch action {
	case ActionRefresh:
		return engine == "nftables" || engine == "iptables" || engine == "haproxy"
	case ActionRestart:
		return slices.Contains([]string{"nftables", "iptables", "haproxy", "realm", "gre", "frp", "rathole"}, engine)
	}
	return false
}

var ownerID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
var clock = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

func minutesOf(value string) (int, bool) {
	if !clock.MatchString(value) {
		return 0, false
	}
	h, _ := strconv.Atoi(value[:2])
	m, _ := strconv.Atoi(value[3:])
	return h*60 + m, true
}

// window parses "HH:MM-HH:MM"; a start after the end wraps past midnight.
func window(value string) (start, end int, ok bool) {
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return 0, 0, false
	}
	a, okA := minutesOf(parts[0])
	b, okB := minutesOf(parts[1])
	return a, b, okA && okB && a != b
}

func (p *Plan) normalize() {
	p.Name = strings.TrimSpace(p.Name)
	if p.Scope == nil {
		p.Scope = []string{}
	}
	slices.Sort(p.Scope)
	p.Scope = slices.Compact(p.Scope)
	slices.Sort(p.Trigger.Times)
	p.Trigger.Times = slices.Compact(p.Trigger.Times)
	slices.Sort(p.Trigger.Days)
	p.Trigger.Days = slices.Compact(p.Trigger.Days)
	if p.Guards.QuietMbps > 0 && p.Guards.QuietTimeout == "" {
		p.Guards.QuietTimeout = "skip"
	}
}

func validTimes(times []string) bool {
	if len(times) < 1 || len(times) > 6 {
		return false
	}
	for _, t := range times {
		if _, ok := minutesOf(t); !ok {
			return false
		}
	}
	return true
}

// Validate checks a normalized plan.
func (p Plan) Validate() error {
	if p.Name == "" || len([]rune(p.Name)) > 60 || strings.IndexFunc(p.Name, unicode.IsControl) >= 0 {
		return errors.New("name must be 1–60 characters")
	}
	if !slices.Contains([]string{ActionRefresh, ActionRestart, ActionReboot}, p.Action) {
		return errors.New("unknown maintenance action")
	}
	if len(p.Scope) > 128 {
		return errors.New("select at most 128 connections or resources")
	}
	for _, id := range p.Scope {
		if !ownerID.MatchString(id) {
			return errors.New("invalid connection or resource in scope")
		}
	}
	t := p.Trigger
	switch t.Kind {
	case TriggerInterval:
		if t.Hours < 1 || t.Hours > 168 {
			return errors.New("interval must be 1–168 hours")
		}
	case TriggerDaily:
		if !validTimes(t.Times) {
			return errors.New("enter 1–6 times as HH:MM")
		}
	case TriggerWeekly:
		if !validTimes(t.Times) || len(t.Days) < 1 || len(t.Days) > 7 || t.Days[0] < 0 || t.Days[len(t.Days)-1] > 6 {
			return errors.New("choose weekdays and 1–6 times as HH:MM")
		}
	case TriggerUptime:
		if p.Action != ActionReboot || t.UptimeDays < 1 || t.UptimeDays > 60 || !validTimes(t.Times) {
			return errors.New("uptime triggers reboot after 1–60 days at chosen times")
		}
	case TriggerHealth:
		if t.Minutes < 1 || t.Minutes > 120 {
			return errors.New("a health condition must hold for 1–120 minutes")
		}
		switch t.Condition {
		case ConditionDown:
		case ConditionLatency:
			if t.LatencyMs < 20 || t.LatencyMs > 5000 {
				return errors.New("latency limit must be 20–5000 ms")
			}
		default:
			return errors.New("unknown health condition")
		}
	default:
		return errors.New("unknown trigger")
	}
	if p.Action == ActionReboot && t.Kind != TriggerHealth && len(p.Scope) > 0 {
		return errors.New("a scheduled reboot applies to the whole server; leave the scope empty")
	}
	g := p.Guards
	if g.Window != "" {
		if _, _, ok := window(g.Window); !ok {
			return errors.New("window must be HH:MM-HH:MM")
		}
	}
	switch {
	case g.QuietMbps < 0 || g.QuietMbps > 100000 || g.QuietWait < 0 || g.QuietWait > 360:
		return errors.New("quiet traffic must be 0–100000 Mbps with a 0–360 minute wait")
	case g.QuietMbps > 0 && g.QuietTimeout != "run" && g.QuietTimeout != "skip":
		return errors.New("choose what happens when traffic stays busy")
	case g.Cooldown < 0 || g.Cooldown > 10080:
		return errors.New("cooldown must be 0–10080 minutes")
	case g.MaxPerDay < 1 || g.MaxPerDay > 48:
		return errors.New("runs per day must be 1–48")
	case g.MinUptime < 0 || g.MinUptime > 1440:
		return errors.New("minimum uptime must be 0–1440 minutes")
	case g.Notice < 0 || g.Notice > 60:
		return errors.New("notice must be 0–60 minutes")
	case g.Stagger < 0 || g.Stagger > 300:
		return errors.New("stagger must be 0–300 seconds")
	}
	return nil
}
