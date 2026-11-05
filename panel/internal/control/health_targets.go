package control

import (
	"net/netip"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/maintenance"
)

var greAddress = regexp.MustCompile(`(?m)ip addr add ([0-9.]+)/30 dev `)

// grePeer derives the other usable host of the unit's /30 inner network.
// Modern and legacy units both number their ends .1 and .2 (or .2 and .1).
func grePeer(unit string) string {
	match := greAddress.FindStringSubmatch(unit)
	if match == nil {
		return ""
	}
	a, e := netip.ParseAddr(match[1])
	if e != nil || !a.Is4() {
		return ""
	}
	b := a.As4()
	switch b[3] & 3 {
	case 1:
		b[3]++
	case 2:
		b[3]--
	default:
		return ""
	}
	return netip.AddrFrom4(b).String()
}

func displayName(name, id string) string {
	if strings.TrimSpace(name) != "" {
		return name
	}
	return id
}

// firstPort is the listen port a target without its own port forwards to.
func firstPort(ports string) int {
	value := strings.FieldsFunc(ports, func(r rune) bool { return r == '-' || r == ',' || r == ':' })
	if len(value) == 0 {
		return 0
	}
	n, _ := strconv.Atoi(value[0])
	return n
}

// healthTargets lists what the monitor probes: every enabled connection's
// destinations (TCP connect, or ICMP for UDP-only services), managed service
// units, and GRE peers over the tunnel.
func healthTargets(inventory Inventory) []health.Target {
	out := []health.Target{}
	add := func(t health.Target) {
		if len(out) < health.MaxTargets {
			out = append(out, t)
		}
	}
	for _, c := range inventory.Connections {
		if !c.Enabled {
			continue
		}
		name := displayName(c.Name, c.ID)
		if c.Engine == "haproxy" || c.Engine == "realm" {
			add(health.Target{Key: c.ID + "|service", Owner: c.ID, Name: name, Engine: c.Engine, Kind: health.KindService, Unit: "gtm-" + c.ID})
		}
		// One probe per distinct endpoint; it stands for every position
		// (1-based, as the Bash state numbers them) with that endpoint.
		seen := map[string]int{}
		for i, t := range effectiveTargets(c) {
			address, e := netip.ParseAddr(t.IP)
			if e != nil || address.Zone() != "" {
				continue
			}
			port := t.Port
			if port == 0 {
				port = firstPort(c.Ports)
			}
			kind := health.KindTCP
			if c.Protocol == "udp" {
				kind, port = health.KindICMP, 0
			}
			key := c.ID + "|" + kind + "|" + address.String()
			if port > 0 {
				key += "|" + strconv.Itoa(port)
			}
			if at, ok := seen[key]; ok {
				out[at].Indexes = append(out[at].Indexes, i+1)
				continue
			}
			if len(out) >= health.MaxTargets {
				continue
			}
			seen[key] = len(out)
			add(health.Target{Key: key, Owner: c.ID, Name: name, Engine: c.Engine, Kind: kind, Address: address.String(), Port: port, Indexes: []int{i + 1}})
		}
	}
	for _, r := range inventory.Resources {
		name := displayName(r.Name, r.ID)
		add(health.Target{Key: r.ID + "|service", Owner: r.ID, Name: name, Engine: r.Engine, Kind: health.KindService, Unit: r.ID})
		if r.Engine == "gre" && r.Peer != "" {
			add(health.Target{Key: r.ID + "|icmp|" + r.Peer, Owner: r.ID, Name: name, Engine: r.Engine, Kind: health.KindICMP, Address: r.Peer})
		}
	}
	return out
}

// serviceResults reads systemd states already collected by the inventory.
func serviceResults(inventory Inventory, targets []health.Target) map[string]health.Result {
	states := map[string]string{}
	for _, c := range inventory.Connections {
		states["gtm-"+c.ID] = c.Status
	}
	for _, r := range inventory.Resources {
		states[r.ID] = r.Status
	}
	out := map[string]health.Result{}
	for _, t := range targets {
		if t.Kind != health.KindService {
			continue
		}
		state := states[t.Unit]
		if state == "active" {
			out[t.Key] = health.Result{OK: true}
		} else if state != "" && state != "unknown" {
			out[t.Key] = health.Result{Error: state}
		}
	}
	return out
}

// maintenanceOwners lists what plans can act on.
func maintenanceOwners(inventory Inventory) []maintenance.Owner {
	out := []maintenance.Owner{}
	for _, c := range inventory.Connections {
		if c.Enabled {
			out = append(out, maintenance.Owner{ID: c.ID, Name: displayName(c.Name, c.ID), Engine: c.Engine})
		}
	}
	for _, r := range inventory.Resources {
		out = append(out, maintenance.Owner{ID: r.ID, Name: displayName(r.Name, r.ID), Engine: r.Engine})
	}
	return out
}
