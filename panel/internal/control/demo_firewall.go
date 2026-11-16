package control

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// demoFirewall models a typical Iranian entry server: UFW active with
// "deny (routed)" kept in iptables-legacy next to Docker in iptables-nft.
type demoFirewall struct {
	settings FirewallSettings
	revision string
	previous *FirewallSettings
	deadline time.Time
	// repaired: the legacy backend got the owned accept (it starts missing,
	// as after "ufw reload" on a host without the refresh timer).
	repaired bool
}

func (d *Demo) firewallState() *demoFirewall {
	x := d.extras()
	if x.firewall == nil {
		x.firewall = &demoFirewall{settings: emptyFirewallSettings(), revision: "none"}
	}
	return x.firewall
}

func demoFirewallRevision(s FirewallSettings) string {
	data, _ := json.Marshal(s)
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func (d *Demo) firewallDemo(r Request) (json.RawMessage, error) {
	fw := d.firewallState()
	now := time.Now().UTC()
	// An unconfirmed change reverts by itself, as the engine's timer would.
	if fw.previous != nil && now.After(fw.deadline) {
		fw.settings, fw.previous = *fw.previous, nil
		fw.revision = demoFirewallRevision(fw.settings)
	}
	switch r.Action {
	case "firewall":
		return json.Marshal(d.firewallStatusDemo(fw))
	case "firewall-apply":
		if r.Firewall.Revision != fw.revision {
			return nil, errors.New("firewall settings changed; reload and try again")
		}
		input, e := r.Firewall.validate(d.inventory.Connections)
		if e != nil {
			return nil, e
		}
		next := emptyFirewallSettings()
		for _, line := range strings.Split(strings.TrimSpace(input), "\n")[1:] {
			readFirewallSetting(&next, append([]string{}, strings.Split(line, "\t")...))
		}
		if r.Firewall.Seconds > 0 {
			if fw.previous == nil {
				before := fw.settings
				fw.previous = &before
			}
			fw.deadline = now.Add(time.Duration(r.Firewall.Seconds) * time.Second)
		} else {
			fw.previous = nil
		}
		fw.settings, fw.revision = next, demoFirewallRevision(next)
		return json.Marshal("Demo: firewall settings applied. No server settings were changed.")
	case "firewall-confirm":
		fw.previous = nil
		return json.Marshal("Demo: firewall settings confirmed.")
	case "firewall-revert":
		if fw.previous != nil {
			fw.settings, fw.previous = *fw.previous, nil
			fw.revision = demoFirewallRevision(fw.settings)
		}
		return json.Marshal("Demo: firewall settings reverted.")
	case "firewall-repair":
		fw.repaired = true
		return json.Marshal("Demo: owned kernel rules reapplied. No server settings were changed.")
	}
	return nil, errors.New("unknown firewall action")
}

func (d *Demo) firewallStatusDemo(fw *demoFirewall) FirewallStatus {
	s := fw.settings
	v := FirewallStatus{
		Revision: fw.revision, NFT: true, Docker: true,
		UFW:            FirewallUFW{State: "active", Incoming: "deny", Routed: "deny"},
		Tables:         []string{"inet abuse_defender", "inet gtm_panel_metrics"},
		Uplinks:        []string{"eth0"},
		SSH:            []int{22},
		AutoExceptions: []string{"10.202.10.10"},
		Ports:          []FirewallPort{},
		Counters:       []FirewallCounter{},
		Settings:       s,
		Backends: []FirewallBackend{
			{Family: 4, Tool: "iptables", Kind: "nf_tables", Input: "ACCEPT", Forward: "DROP", Guard: true},
			{Family: 4, Tool: "iptables-legacy", Kind: "legacy", Input: "DROP", Forward: "DROP", Guard: fw.repaired},
			{Family: 6, Tool: "ip6tables", Kind: "nf_tables", Input: "ACCEPT", Forward: "ACCEPT"},
		},
	}
	if fw.previous != nil {
		deadline := fw.deadline
		v.Pending = &deadline
	}
	opened := map[string]bool{}
	for _, id := range s.UFW {
		opened[id] = true
	}
	for i, c := range d.inventory.Connections {
		for _, proto := range []string{"tcp", "udp"} {
			if c.Protocol != proto && c.Protocol != "both" {
				continue
			}
			state := "closed"
			switch {
			case opened[c.ID]:
				state = "tagged"
			case i == 0:
				state = "open"
			}
			v.Ports = append(v.Ports, FirewallPort{ID: c.ID, Protocol: proto, Port: c.Ports, UFW: state})
		}
	}
	rules := false
	for i, a := range s.Access {
		weight := uint64(i+1) * 37
		if a.Mode != "off" {
			v.Counters = append(v.Counters, FirewallCounter{Rule: a.ID + "-" + a.Mode, Packets: weight * 11, Bytes: weight * 11 * 60})
		}
		if a.Rate > 0 {
			v.Counters = append(v.Counters, FirewallCounter{Rule: a.ID + "-rate", Packets: weight * 3, Bytes: weight * 180})
		}
		if a.PerIP > 0 {
			v.Counters = append(v.Counters, FirewallCounter{Rule: a.ID + "-conn", Packets: weight, Bytes: weight * 60})
		}
		rules = rules || a.Mode != "off" || a.Rate > 0 || a.PerIP > 0
	}
	if s.PrivateRanges {
		v.Counters = append(v.Counters, FirewallCounter{Rule: "private", Packets: 1294, Bytes: 77640})
	}
	if s.SMTP {
		v.Counters = append(v.Counters, FirewallCounter{Rule: "smtp", Packets: 18, Bytes: 1080})
	}
	if rules || s.PrivateRanges || s.SMTP {
		applied := true
		v.Applied = &applied
	}
	return v
}
