package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// Demo is explicitly simulated and cannot execute system commands.
type Demo struct {
	mu        sync.Mutex
	inventory Inventory
	counter   int
	metrics   MetricsView
}

func NewDemo() *Demo {
	d := &Demo{counter: 4, inventory: Inventory{Version: "1.3.0", Demo: true, Host: Host{Hostname: "edge-01", OS: "Ubuntu 24.04 LTS", Addresses: []string{"203.0.113.10", "2001:db8::10"}, Uptime: "72h0m", MemoryTotal: 1073741824, MemoryAvailable: 805306368, Load: "0.03 0.02 0.01"}, Capabilities: model.Capabilities(), Resources: []Resource{}, Components: []Component{{ID: "nftables", Installed: true}, {ID: "iptables", Installed: true}, {ID: "haproxy", Installed: true}, {ID: "realm", Installed: true}, {ID: "frp", Installed: false}, {ID: "rathole", Installed: false}}}}
	d.inventory.EngineProfiles = model.EngineProfiles()
	for index := range d.inventory.Components {
		c := &d.inventory.Components[index]
		c.Version = map[string]string{"haproxy": "2.8.5", "nftables": "1.0.9", "iptables": "1.8.10", "realm": "2.9.6"}[c.ID]
		c.Compatibility = compatibility(c.ID, c.Version)
	}
	for index, engine := range []string{"haproxy", "nftables", "realm"} {
		c := model.Connection{ID: fmt.Sprintf("F%06d", index+1), Name: []string{"Reality · Frankfurt", "WireGuard · Stockholm", "Private relay"}[index], Engine: engine, Protocol: []string{"tcp", "udp", "both"}[index], Bind: "203.0.113.10", Ports: []string{"443", "51820", "8443"}[index], Strategy: "single", Enabled: true, SNAT: "masquerade", Interface: "any", Targets: []model.Target{{IP: []string{"198.51.100.20", "198.51.100.30", "198.51.100.40"}[index], Port: []int{443, 51820, 8443}[index], Weight: 1}}, Options: map[string]string{}, Status: "active"}
		c.Name = []string{"Reality Frankfurt", "WireGuard Stockholm", "Private relay"}[index]
		rows, _ := c.Rows(c.ID)
		c.Revision = model.Revision(rows[0])
		d.inventory.Connections = append(d.inventory.Connections, c)
	}
	d.metrics = MetricsView{Settings: MetricsSettings{Interval: 60, IDs: []string{}}, Counters: map[string]Traffic{}, Since: time.Now().UTC(), Policies: map[string]TrafficPolicy{}, History: map[string][]TrafficPoint{}, Cycles: map[string][]TrafficCycle{}}
	return d
}
func (d *Demo) Do(_ context.Context, r Request) (json.RawMessage, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	var result any = "Demo operation completed. No server settings were changed."
	switch r.Action {
	case "inventory":
		result = d.inventory
	case "metrics":
		m := Metrics{view: d.metrics}
		result = m.Summary()
	case "metrics-history":
		m := Metrics{view: d.metrics}
		archive, e := m.Archive(r.Traffic.ID)
		if e != nil {
			return nil, e
		}
		result = archive
	case "metrics-configure":
		if r.MetricsRevision != nil && *r.MetricsRevision != d.metrics.Revision {
			return nil, errors.New("traffic settings changed; refresh before saving")
		}
		if e := metricsValid(r.Metrics); e != nil {
			return nil, e
		}
		d.metrics.Settings = r.Metrics
		d.metrics.Revision++
		result = map[string]any{"ok": true, "revision": d.metrics.Revision}
	case "metrics-reset", "metrics-policy", "metrics-forget":
		m := &Metrics{view: cloneMetrics(d.metrics)}
		if r.Traffic.Revision != m.view.Revision || !trafficID(r.Traffic.ID) {
			return nil, errors.New("refresh traffic settings")
		}
		_, known := m.view.Counters[r.Traffic.ID]
		_, policyKnown := m.view.Policies[r.Traffic.ID]
		available := trafficAvailable(d.inventory, r.Traffic.ID)
		if !available && !known && !policyKnown {
			return nil, errors.New("resource not found")
		}
		if r.Action == "metrics-forget" && available {
			return nil, errors.New("remove connection first")
		}
		if r.Action == "metrics-policy" && !validTrafficPolicy(r.Traffic.Policy) {
			return nil, errors.New("invalid policy")
		}
		m.applyTrafficChange(r.Action, r.Traffic, time.Now().UTC())
		if e := m.validateLedger(); e != nil {
			return nil, e
		}

		m.view.Revision++
		d.metrics = m.view
		result = map[string]any{"ok": true, "revision": d.metrics.Revision}
	case "create":
		rows, e := r.Connection.Rows("F000000")
		if e != nil {
			return nil, e
		}
		for _, row := range rows {
			c, _, e := model.ParseState(row)
			if e != nil {
				return nil, e
			}
			d.counter++
			c[0].ID = fmt.Sprintf("F%06d", d.counter)
			c[0].Revision = model.Revision(row)
			c[0].Status = "configured"
			d.inventory.Connections = append(d.inventory.Connections, c[0])
		}
	case "delete", "enable", "disable", "update":
		next := []model.Connection{}
		for _, c := range d.inventory.Connections {
			selected := false
			for _, s := range r.Selected {
				if s.ID == c.ID {
					if s.Revision != c.Revision {
						return nil, errors.New("refresh the list")
					}
					selected = true
				}
			}
			if selected {
				switch r.Action {
				case "delete":
					continue
				case "enable":
					c.Enabled = true
				case "disable":
					c.Enabled = false
				case "update":
					rows, e := r.Connection.Rows(c.ID)
					if e != nil {
						return nil, e
					}
					parsed, _, e := model.ParseState(rows[0])
					if e != nil {
						return nil, e
					}
					c = parsed[0]
				}
			}
			next = append(next, c)
		}
		d.inventory.Connections = next
	case "install":
		for i := range d.inventory.Components {
			for _, id := range r.Components {
				if d.inventory.Components[i].ID == id {
					d.inventory.Components[i].Installed = true
				}
			}
		}
	case "gre-create":
		g := r.GRE
		d.inventory.Resources = append(d.inventory.Resources, Resource{ID: fmt.Sprintf("gre-tun-%d", g.ID), Engine: "gre", Name: fmt.Sprintf("GRE %d", g.ID), Role: g.Role, Status: "active", Configured: true, Interface: fmt.Sprintf("gre%d", g.ID)})
		d.inventory.Resources[len(d.inventory.Resources)-1].Revision = model.Revision("demo unit "+d.inventory.Resources[len(d.inventory.Resources)-1].ID) + ":-"
	case "reverse-create":
		if _, e := r.Reverse.Input(); e != nil {
			return nil, e
		}
		v := r.Reverse
		d.inventory.Resources = append(d.inventory.Resources, Resource{ID: "gtm-" + v.Engine + "-" + v.Role + "-" + v.Name, Engine: v.Engine, Name: v.Name, Role: v.Role, Status: "active", Configured: true})
		d.inventory.Resources[len(d.inventory.Resources)-1].Revision = model.Revision("demo unit "+d.inventory.Resources[len(d.inventory.Resources)-1].ID) + ":-"
	case "gre-delete", "reverse-delete":
		next := []Resource{}
		for _, v := range d.inventory.Resources {
			if v.ID != r.Service {
				next = append(next, v)
			}
		}
		d.inventory.Resources = next
	case "resource-rename":
		if r.ResourceName.Name != "" && !resourceNameValid(r.ResourceName.Name) {
			return nil, errors.New("invalid display name")
		}
		for i := range d.inventory.Resources {
			if d.inventory.Resources[i].ID == r.ResourceName.ID {
				if r.ResourceName.Revision != d.inventory.Resources[i].Revision {
					return nil, errors.New("refresh resource")
				}
				d.inventory.Resources[i].Name = r.ResourceName.Name
				if d.inventory.Resources[i].Name == "" {
					resource := d.inventory.Resources[i]
					d.inventory.Resources[i].Name = strings.TrimPrefix(resource.ID, "gtm-"+resource.Engine+"-"+resource.Role+"-")
				}
				rowHash := "-"
				if r.ResourceName.Name != "" {
					rowHash = model.Revision(r.ResourceName.Name)
				}
				d.inventory.Resources[i].Revision = model.Revision("demo unit "+r.ResourceName.ID) + ":" + rowHash
			}
		}
	case "service":
		for i := range d.inventory.Resources {
			if d.inventory.Resources[i].ID == r.Service {
				d.inventory.Resources[i].Status = "active"
				if r.Verb == "stop" {
					d.inventory.Resources[i].Status = "inactive"
				}
			}
		}
	case "plan":
		result = "Demo configuration preview. Native validation is performed on a Linux installation."
	case "logs":
		result = "Demo log viewer. Production loads only the last 100 lines of the selected managed service."
	case "doctor":
		result = "Demo diagnostics. No live network probes were run."
	default:
		return nil, errors.New("unsupported operation")
	}
	return json.Marshal(result)
}
