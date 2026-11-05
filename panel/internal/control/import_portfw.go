package control

import (
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// parsePortfwImport converts Port Forward Manager (portfw / portfw-nft) rules,
// as printed by the engine's `portfw-rules` ("id source target dest proto"),
// into kernel connections. Its port lists map one-to-one in order, so each
// run of consecutive ports that stays consecutive on the destination side
// becomes one range record (shifted ranges need nftables).
func parsePortfwImport(text, engine string) ([]model.Connection, []string, error) {
	if engine != "nftables" && engine != "iptables" {
		return nil, nil, errors.New("Port Forward Manager rules import as nftables or iptables forwards")
	}
	cs := []model.Connection{}
	warnings := []string{}
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		f := strings.Split(line, "\t")
		if len(f) != 5 || !oneOf(f[4], "tcp", "udp", "both") {
			return nil, nil, errors.New("unexpected Port Forward Manager rule format")
		}
		source, e := expandPortList(f[1])
		if e != nil {
			return nil, nil, fmt.Errorf("rule %s: %w", f[0], e)
		}
		dest, e := expandPortList(f[3])
		if e != nil {
			return nil, nil, fmt.Errorf("rule %s: %w", f[0], e)
		}
		if len(source) != len(dest) {
			return nil, nil, fmt.Errorf("rule %s: source and destination port counts differ", f[0])
		}
		target := f[2]
		if a, e := netip.ParseAddr(target); e != nil || !a.Is4() {
			if !model.ValidHostname(target) {
				return nil, nil, fmt.Errorf("rule %s: invalid destination %q", f[0], target)
			}
		}
		local, remote := []string{}, []string{}
		for i := 0; i < len(source); {
			j := i
			for j+1 < len(source) && source[j+1] == source[j]+1 && dest[j+1] == dest[j]+1 && j+1-i < model.SpanMax {
				j++
			}
			local = append(local, model.Span{First: source[i], Last: source[j]}.String())
			remote = append(remote, model.Span{First: dest[i], Last: dest[j]}.String())
			if engine == "iptables" && source[i] != dest[i] && j > i {
				return nil, nil, fmt.Errorf("rule %s maps %d-%d to other ports; import it as nftables", f[0], source[i], source[j])
			}
			i = j + 1
		}
		for start := 0; start < len(local); start += 32 {
			end := min(start+32, len(local))
			c := model.Connection{Name: "portfw-" + f[0], Engine: engine, Protocol: f[4], Bind: "0.0.0.0", Ports: strings.Join(local[start:end], ","), Strategy: "single", Enabled: true, SNAT: "masquerade", Interface: "any", Targets: []model.Target{{IP: target, Port: dest[0], Weight: 1}}, Options: map[string]string{}, PortMode: "map", RemotePorts: strings.Join(remote[start:end], ",")}
			if model.ValidHostname(target) {
				// Every A record becomes a destination, as portfw's round robin.
				c.Strategy = "random"
				if engine == "nftables" {
					c.Strategy = "roundrobin"
				}
			}
			if len(local) > 32 {
				c.Name = fmt.Sprintf("portfw-%s-%d", f[0], start/32+1)
			}
			cs = append(cs, c)
		}
		if model.ValidHostname(target) {
			warnings = append(warnings, fmt.Sprintf("Rule %s uses %s: every address it resolves to receives traffic and is refreshed every 5 minutes.", f[0], target))
		}
	}
	if len(cs) == 0 {
		return nil, nil, errors.New("no Port Forward Manager rules were found on this server")
	}
	warnings = append(warnings, "Remove these rules from Port Forward Manager (or stop portfw-nft) after importing: overlapping NAT from two managers is refused.")
	return cs, warnings, nil
}

// expandPortList expands "2001-2003,2010" in order (portfw's own limits).
func expandPortList(value string) ([]int, error) {
	out := []int{}
	for _, word := range strings.Split(value, ",") {
		first, last, ranged := strings.Cut(strings.TrimSpace(word), "-")
		a, e := strconv.Atoi(first)
		if e != nil || a < 1 || a > 65535 {
			return nil, errors.New("invalid port list")
		}
		b := a
		if ranged {
			if b, e = strconv.Atoi(last); e != nil || b < a || b > 65535 {
				return nil, errors.New("invalid port range")
			}
		}
		for p := a; p <= b; p++ {
			out = append(out, p)
		}
		if len(out) > 4096 {
			return nil, errors.New("more than 4096 ports in one rule")
		}
	}
	return out, nil
}
