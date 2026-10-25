package control

import (
	"context"
	"fmt"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"net"
	"strings"
)

// Demo rendering is illustrative and in-process. Never invoke the host helper.
type demoConfigRunner struct{ connections []model.Connection }

func (r demoConfigRunner) Run(_ context.Context, _ string, args []string, input string) (string, error) {
	if len(args) < 3 {
		return "", fmt.Errorf("invalid demo operation")
	}
	switch args[2] {
	case "recovery-revision":
		var rows []string
		for _, c := range r.connections {
			v, e := c.Rows(c.ID)
			if e != nil {
				return "", e
			}
			rows = append(rows, v...)
		}
		return model.Revision(strings.Join(rows, "\n")), nil
	case "state":
		var rows []string
		for _, c := range r.connections {
			v, e := c.Rows(c.ID)
			if e != nil {
				return "", e
			}
			rows = append(rows, v...)
		}
		return strings.Join(rows, "\n"), nil
	case "config-render":
		cs, _, e := model.ParseState(input)
		if e != nil || len(cs) != 1 {
			return "", fmt.Errorf("invalid demo record")
		}
		c := cs[0]
		value := func(key string) string {
			if v, ok := c.Options[key]; ok {
				return v
			}
			cap, _ := c.Capability()
			for _, o := range cap.Options {
				if o.Key == key {
					return o.Default
				}
			}
			return ""
		}
		endpoint := func(ip string, p int) string {
			if strings.Contains(ip, ":") {
				return fmt.Sprintf("[%s]:%d", ip, p)
			}
			return fmt.Sprintf("%s:%d", ip, p)
		}
		var b strings.Builder
		fmt.Fprintln(&b, "# DEMO: illustrative output; production uses the Bash renderer")
		if c.Engine == "haproxy" {
			demoHAConfig(&b, c, value)
		} else if c.Engine == "realm" {
			fmt.Fprintf(&b, "[log]\nlevel = %q\n[network]\ntcp_timeout = %s\nudp_timeout = %s\n[[endpoints]]\nlisten = %q\nremote = %q\n", value("log"), value("tcp_timeout"), value("udp_timeout"), net.JoinHostPort(c.Bind, c.Ports), endpoint(c.Targets[0].IP, c.Targets[0].Port))
		} else {
			fmt.Fprintf(&b, "# %s owned %s forwarding\n# %s:%s -> %s\n", c.Engine, c.Protocol, c.Bind, c.Ports, endpoint(c.Targets[0].IP, c.Targets[0].Port))
			if c.SNAT == "masquerade" {
				fmt.Fprintln(&b, "# Source policy: masquerade")
			}
			if c.Engine == "nftables" {
				fmt.Fprintln(&b, "table inet gre_manager {\n    # Named owned DNAT rules are rendered on Linux\n}")
				for _, proto := range []string{"tcp", "udp"} {
					if c.Protocol != proto && c.Protocol != "both" {
						continue
					}
					fmt.Fprintf(&b, "add rule inet gre_manager pre ip daddr %s %s dport %s counter dnat ip to %s comment \"gtm-%s\"\n", c.Bind, proto, c.Ports, endpoint(c.Targets[0].IP, c.Targets[0].Port), c.ID)
				}
			} else {
				fmt.Fprintln(&b, "*nat\n# Owned GTM chains are rendered on Linux\nCOMMIT")
				for _, proto := range []string{"tcp", "udp"} {
					if c.Protocol != proto && c.Protocol != "both" {
						continue
					}
					fmt.Fprintf(&b, "-A GTM_PRE -d %s -p %s --dport %s -m comment --comment gtm-%s -j DNAT --to-destination %s\n", c.Bind, proto, c.Ports, c.ID, endpoint(c.Targets[0].IP, c.Targets[0].Port))
				}
			}
		}
		return b.String(), nil
	}
	return "", fmt.Errorf("unsupported demo operation")
}
