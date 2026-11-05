package control

import (
	"context"
	"errors"
	"os"
	"slices"
	"strconv"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
)

// writePrivate replaces path with data (mode 600) through a temporary file.
func writePrivate(path string, data []byte) error {
	temp := path + ".tmp"
	if e := os.WriteFile(temp, data, 0600); e != nil {
		return e
	}
	if e := os.Rename(temp, path); e != nil {
		_ = os.Remove(temp)
		return e
	}
	return nil
}

// Protection is what a connection or GRE form chose for health checks:
// monitor the owner, fail over between its destinations (kernel forwards
// with two or more), send its outages externally, and turn health checks
// on when they are off.
type Protection struct {
	Monitor      bool `json:"monitor"`
	Failover     bool `json:"failover"`
	Notify       bool `json:"notify"`
	EnableHealth bool `json:"enable_health"`
}

func setMember(list []string, id string, member bool) []string {
	out := slices.DeleteFunc(slices.Clone(list), func(v string) bool { return v == id })
	if member {
		out = append(out, id)
	}
	return out
}

// applyProtection updates health settings for owners in one revision-checked
// save. Failover is kept only for eligible forwards.
func (m *Manager) applyProtection(ctx context.Context, owners []string, p Protection) error {
	o := m.Ops
	if o == nil || o.Health == nil || len(owners) == 0 {
		return nil
	}
	inventory, e := m.Inventory(ctx)
	if e != nil {
		return e
	}
	eligible := map[string]bool{}
	for _, c := range inventory.Connections {
		eligible[c.ID] = failoverEligible(c.Engine, c.Enabled, len(effectiveTargets(c)))
	}
	now := time.Now().UTC()
	view := o.Health.View(now, time.UTC)
	s := view.Settings
	if p.EnableHealth {
		s.Enabled = true
	}
	for _, id := range owners {
		s.Ignore = setMember(s.Ignore, id, !p.Monitor)
		s.Quiet = setMember(s.Quiet, id, !p.Notify)
		if len(id) == 7 && id[0] == 'F' {
			s.Failover = setMember(s.Failover, id, p.Failover && p.Monitor && eligible[id])
		}
	}
	if len(s.Failover) > health.MaxFailover {
		return errors.New("failover is limited to 32 forwards")
	}
	if e := o.Health.Configure(now, s, view.Revision); e != nil {
		return e
	}
	o.Notify.SetQuiet(s.Quiet)
	o.invalidate()
	return nil
}

func greOwner(id int) string { return "gre-tun-" + strconv.Itoa(id) }

// executeGuarded runs a forwarding change with its form's protection choices
// and optional confirm-or-revert window.
func (m *Manager) executeGuarded(ctx context.Context, r Request) (any, error) {
	protect, minutes := r.Protect, r.SafeMinutes
	if minutes != 0 && (!safeActions[r.Action] || minutes < 2 || minutes > 30) {
		return nil, errors.New("safe apply needs a forwarding change and 2–30 minutes")
	}
	if (protect != nil || minutes != 0) && m.Ops == nil {
		return nil, errors.New("health and safe apply are unavailable on this broker")
	}
	before := map[string]bool{}
	if protect != nil && r.Action == "create" {
		current, _, e := m.state(ctx)
		if e != nil {
			return nil, e
		}
		for _, c := range current {
			before[c.ID] = true
		}
	}
	inner := r
	inner.Protect, inner.SafeMinutes = nil, 0
	result, e := m.Execute(ctx, inner)
	if e != nil {
		return result, e
	}
	if protect != nil {
		owners := []string{}
		switch r.Action {
		case "create":
			current, _, e := m.state(ctx)
			if e != nil {
				return result, e
			}
			for _, c := range current {
				if !before[c.ID] {
					owners = append(owners, c.ID)
				}
			}
		case "gre-create":
			if r.GRE.ID > 0 {
				owners = append(owners, greOwner(r.GRE.ID))
			}
		default:
			for _, s := range r.Selected {
				owners = append(owners, s.ID)
			}
		}
		if e := m.applyProtection(ctx, owners, *protect); e != nil {
			return result, errors.New("saved, but the health choices were not applied: " + e.Error())
		}
	}
	if minutes != 0 {
		r.SafeMinutes = minutes
		if e := m.armSafe(ctx, r, time.Now().UTC()); e != nil {
			return result, errors.New("saved, but automatic revert could not be armed: " + e.Error())
		}
	}
	return result, nil
}
