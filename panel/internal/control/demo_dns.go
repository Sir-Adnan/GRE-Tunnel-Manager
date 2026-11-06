package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"hash/fnv"
	"slices"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

// demoExtras holds the simulated server DNS, list order and pending change.
type demoExtras struct {
	dns      ServerDNS
	order    map[string][]string
	safe     *SafeChange
	before   []model.Connection
	policies map[string]DNSPolicy
}

func (d *Demo) extras() *demoExtras {
	if d.extra == nil {
		d.extra = &demoExtras{dns: ServerDNS{Mode: "resolved", Current: []string{"127.0.0.53"}, Upstream: []string{"185.51.200.2", "8.8.8.8"}, Active: []string{"185.51.200.2", "8.8.8.8"}, Servers: []string{}, Original: []string{}, Presets: dnsPresets}, order: map[string][]string{}, policies: map[string]DNSPolicy{}}
	}
	return d.extra
}

// demoAddresses resolves any valid name to stable documentation addresses.
func demoAddresses(name string, family int) []string {
	h := fnv.New32a()
	_, _ = h.Write([]byte(name))
	n := h.Sum32()
	count := 1 + int(n%3)
	out := []string{}
	for i := 0; i < count; i++ {
		if family == 6 {
			out = append(out, fmt.Sprintf("2001:db8:%x::%d", n%0xffff, i+10))
		} else {
			out = append(out, fmt.Sprintf("203.0.113.%d", 20+int(n%180)+i))
		}
	}
	return out
}

func demoLatency(server string) (float64, bool) {
	h := fnv.New32a()
	_, _ = h.Write([]byte(server))
	n := h.Sum32()
	if n%11 == 0 {
		return 0, false
	}
	return 8 + float64(n%9000)/100, true
}

// demoResolve fills Resolved for connections with DNS names.
func (d *Demo) demoResolve() {
	names := []DNSName{}
	policies := d.extras().policies
	seen := map[string]bool{}
	for i, c := range d.inventory.Connections {
		if !hasHosts(c) {
			d.inventory.Connections[i].Resolved = nil
			continue
		}
		family := 4
		if strings.Contains(c.Bind, ":") {
			family = 6
		}
		resolved := []model.Target{}
		for _, t := range c.Targets {
			if !t.IsHost() {
				resolved = append(resolved, t)
				continue
			}
			policy, ok := policies[t.IP]
			if !ok {
				policy = DNSPolicy{Name: t.IP, Every: 5, Mode: "all"}
			}
			addresses := demoAddresses(t.IP, family)
			if policy.Mode == "first" {
				addresses = addresses[:1]
			}
			for _, a := range addresses {
				resolved = append(resolved, model.Target{IP: a, Port: t.Port, PortLast: t.PortLast, Weight: t.Weight})
			}
			if !seen[t.IP] {
				seen[t.IP] = true
				names = append(names, DNSName{Name: t.IP, Family: family, Checked: time.Now().Unix() - 90, Every: policy.Every, Mode: policy.Mode, Addresses: demoAddresses(t.IP, family)})
			}
		}
		d.inventory.Connections[i].Resolved = resolved
	}
	d.inventory.DNS = names
}

func (d *Demo) dnsDemo(r Request) (json.RawMessage, error) {
	x := d.extras()
	in := r.DNS
	switch r.Action {
	case "dns":
		return json.Marshal(x.dns)
	case "dns-test":
		servers, e := dnsTestServers(in)
		if e != nil {
			return nil, e
		}
		out := []DNSProbe{}
		for _, s := range servers {
			rtt, ok := demoLatency(s)
			p := DNSProbe{Server: s, Tried: 3}
			if ok {
				p.OK, p.RTT = 3, rtt
			} else {
				p.Error = "timeout"
			}
			out = append(out, p)
		}
		time.Sleep(600 * time.Millisecond)
		return json.Marshal(out)
	case "dns-resolve":
		if !model.ValidHostname(in.Name) {
			return nil, errors.New("enter a domain name such as backend.example.com")
		}
		family := in.Family
		if family != 6 {
			family = 4
		}
		addresses := demoAddresses(in.Name, family)
		if strings.HasPrefix(in.Name, "missing.") {
			addresses = []string{}
		}
		return json.Marshal(DNSResolve{Name: in.Name, Family: family, Addresses: addresses})
	case "dns-apply":
		servers, e := in.servers(4)
		if e != nil {
			return nil, e
		}
		if !x.dns.Managed {
			x.dns.Original = slices.Clone(x.dns.Upstream)
		}
		x.dns.Managed, x.dns.Servers, x.dns.Upstream = true, servers, servers
		x.dns.Active = slices.Clone(servers)
		return json.Marshal("Demo: DNS servers set to " + strings.Join(servers, " ") + ". No server settings were changed.")
	case "dns-restore":
		if x.dns.Managed {
			x.dns.Upstream = x.dns.Original
			x.dns.Active = slices.Clone(x.dns.Original)
		}
		x.dns.Managed, x.dns.Servers, x.dns.Original = false, []string{}, []string{}
		return json.Marshal("Demo: original DNS restored.")
	case "dns-policy":
		if in.Policy == nil || !in.Policy.valid() {
			return nil, errors.New("choose a refresh interval of 1–60 minutes and all or first address")
		}
		x.policies[in.Policy.Name] = *in.Policy
		d.demoResolve()
		return json.Marshal("Demo: refresh policy saved.")
	case "dns-refresh":
		d.demoResolve()
		out := []DNSRefresh{}
		for _, n := range d.inventory.DNS {
			out = append(out, DNSRefresh{Name: n.Name, Family: n.Family, Status: "same", Addresses: n.Addresses})
		}
		return json.Marshal(out)
	}
	return nil, errors.New("unknown DNS action")
}

func (d *Demo) orderDemo(r Request) (json.RawMessage, error) {
	x := d.extras()
	if r.Action == "ui-order-save" {
		if !orderLists[r.Order.List] || !validOrder(r.Order.IDs) {
			return nil, errors.New("invalid list order")
		}
		x.order[r.Order.List] = r.Order.IDs
	}
	return json.Marshal(x.order)
}

func (d *Demo) safeDemo(r Request) (json.RawMessage, error) {
	x := d.extras()
	switch r.Action {
	case "change-confirm":
		x.safe, x.before = nil, nil
	case "change-revert":
		if x.safe == nil {
			return nil, errors.New("no change is waiting for confirmation")
		}
		d.inventory.Connections = x.before
		d.notices.Emit(notify.Event{Kind: notify.KindChangeReverted, Name: x.safe.Summary, Detail: "restored the configuration from before the change", Args: map[string]string{"reason": "manual"}})
		x.safe, x.before = nil, nil
	}
	return json.Marshal(map[string]any{"pending": x.safe})
}

// demoExpire reverts a pending demo change whose window ended.
func (d *Demo) demoExpire(now time.Time) {
	x := d.extras()
	if x.safe != nil && !now.Before(x.safe.Deadline) {
		d.inventory.Connections = x.before
		d.notices.Emit(notify.Event{Kind: notify.KindChangeReverted, Name: x.safe.Summary, Detail: "restored the configuration from before the change", Args: map[string]string{"reason": "timeout"}})
		x.safe, x.before = nil, nil
	}
}

// guarded mirrors Manager.executeGuarded in the demo.
func (d *Demo) guarded(ctx context.Context, r Request) (json.RawMessage, error) {
	if r.SafeMinutes != 0 && (!safeActions[r.Action] || r.SafeMinutes < 2 || r.SafeMinutes > 30) {
		return nil, errors.New("safe apply needs a forwarding change and 2–30 minutes")
	}
	d.mu.Lock()
	before := slices.Clone(d.inventory.Connections)
	d.mu.Unlock()
	inner := r
	inner.Protect, inner.SafeMinutes = nil, 0
	out, e := d.Do(ctx, inner)
	if e != nil {
		return out, e
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if r.Protect != nil {
		known := map[string]bool{}
		for _, c := range before {
			known[c.ID] = true
		}
		owners := []string{}
		switch r.Action {
		case "create":
			for _, c := range d.inventory.Connections {
				if !known[c.ID] {
					owners = append(owners, c.ID)
				}
			}
		case "gre-create":
			owners = append(owners, greOwner(r.GRE.ID))
		default:
			for _, s := range r.Selected {
				owners = append(owners, s.ID)
			}
		}
		if d.ops == nil {
			d.ops = newDemoOps(demoResources(d.inventory))
		}
		o := d.ops.ops
		now := time.Now().UTC()
		view := o.Health.View(now, time.UTC)
		s := view.Settings
		if r.Protect.EnableHealth {
			s.Enabled = true
		}
		for _, id := range owners {
			s.Ignore = setMember(s.Ignore, id, !r.Protect.Monitor)
			s.Quiet = setMember(s.Quiet, id, !r.Protect.Notify)
			if strings.HasPrefix(id, "F") {
				eligible := false
				for _, c := range d.inventory.Connections {
					if c.ID == id {
						eligible = failoverEligible(c.Engine, c.Enabled, len(effectiveTargets(c)))
					}
				}
				s.Failover = setMember(s.Failover, id, r.Protect.Failover && r.Protect.Monitor && eligible)
			}
		}
		if e := o.Health.Configure(now, s, view.Revision); e != nil {
			return nil, e
		}
	}
	if r.SafeMinutes != 0 {
		x := d.extras()
		now := time.Now().UTC()
		summary := strings.TrimSpace(r.Connection.Name + " " + r.Connection.Ports)
		x.safe = &SafeChange{Action: r.Action, Summary: summary, Point: "20260101T000000-1-1.tsv", Revision: strings.Repeat("a", 64), Started: now, Deadline: now.Add(time.Duration(r.SafeMinutes) * time.Minute)}
		x.before = before
	}
	return out, nil
}
