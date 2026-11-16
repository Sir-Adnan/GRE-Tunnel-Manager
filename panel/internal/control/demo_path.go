package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// pathDemo synthesizes counters that grow with time, so the live packet
// path moves. Kernel forwards are dropped by the legacy backend until the
// Firewall page repairs it; WireGuard Stockholm's destination never answers
// (as in the diagnosis demo) and the pool's third destination stays idle.
func (d *Demo) pathDemo(id string) (json.RawMessage, error) {
	if !model.IDPattern.MatchString(id) {
		return nil, errors.New("invalid connection ID")
	}
	i := slices.IndexFunc(d.inventory.Connections, func(c model.Connection) bool { return c.ID == id })
	if i < 0 {
		return nil, errors.New("Connection not found.")
	}
	c := d.inventory.Connections[i]
	now := time.Now().UTC()
	path := ConnectionPath{ID: id, Engine: c.Engine, Enabled: c.Enabled, Time: now, Stages: []PathStage{}, Drops: []string{}}
	if !c.Enabled {
		return json.Marshal(path)
	}
	seconds := uint64(now.Sub(d.metrics.Since).Seconds()) + 600
	grow := func(base, rate uint64) uint64 { return base + rate*seconds }
	switch c.Engine {
	case "nftables", "iptables":
		dropped := !d.firewallState().repaired && !strings.Contains(c.Bind, ":")
		if dropped {
			path.Drops = append(path.Drops, "iptables-legacy")
		}
		flows := grow(120, 2)
		path.Stages = append(path.Stages, PathStage{Key: "new", Packets: flows, Bytes: flows * 60})
		if c.SNAT == "masquerade" {
			path.Stages = append(path.Stages, PathStage{Key: "snat", Packets: flows, Bytes: flows * 60})
		}
		for n, t := range c.Targets {
			out, back := grow(9000, 140), grow(15000, 260)
			switch {
			case n == 2:
				out, back = 0, 0
			case dropped || id == "F000002":
				back = 0
			}
			path.Stages = append(path.Stages,
				PathStage{Key: "out", Address: t.IP, Packets: out, Bytes: out * 180},
				PathStage{Key: "back", Address: t.IP, Packets: back, Bytes: back * 1100})
		}
	default:
		path.Stages = append(path.Stages, PathStage{Key: "clients", Packets: 14 + seconds%5})
		for _, t := range c.Targets {
			path.Stages = append(path.Stages, PathStage{Key: "upstream", Address: t.IP, Packets: 14 + seconds%5})
		}
	}
	if slices.ContainsFunc(d.firewallState().settings.Access, func(a FirewallAccess) bool { return a.ID == id && (a.Mode != "off" || a.PerIP > 0 || a.Rate > 0) }) {
		blocked := grow(40, 1)
		path.Stages = append(path.Stages, PathStage{Key: "blocked", Packets: blocked, Bytes: blocked * 60})
	}
	return json.Marshal(path)
}

// portTaken mirrors the engine's listener check on create: an enabled
// managed connection already listens on an overlapping port and protocol.
func (d *Demo) portTaken(c model.Connection) error {
	if !c.Enabled {
		return nil
	}
	mine, e := model.ParsePortSpans(c.Ports, true)
	if e != nil {
		return nil
	}
	for _, o := range d.inventory.Connections {
		if !o.Enabled || (c.Protocol != "both" && o.Protocol != "both" && c.Protocol != o.Protocol) {
			continue
		}
		theirs, e := model.ParsePortSpans(o.Ports, true)
		if e != nil {
			continue
		}
		for _, a := range mine {
			for _, b := range theirs {
				if a.First <= b.Last && b.First <= a.Last {
					return fmt.Errorf("Port is reserved by managed connection %s (%s).", o.ID, o.Name)
				}
			}
		}
	}
	return nil
}
