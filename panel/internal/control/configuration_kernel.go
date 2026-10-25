package control

import (
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

var iptablesNative = regexp.MustCompile(`(?m)^-A GTM_PRE -d (\S+)(?: -i (\S+))? -p (tcp|udp) --dport ([0-9]+) [^\n]* -j DNAT --to-destination (\S+)$`)
var nftNative = regexp.MustCompile(`(?m)^add rule inet gre_manager pre (?:ip|ip6) daddr (\S+)(?: iifname "([^"]+)")? (tcp|udp) dport ([0-9]+) counter dnat (?:ip|ip6) to (\S+) comment "gtm-F[0-9]{6}"$`)

// Extract data from a single owned DNAT excerpt. The caller must compare the
// entire regenerated excerpt, including forward/reply/MSS/SNAT companion rules.
// Submitted firewall text is NEVER passed to nft or iptables directly.
func importKernelNative(c model.Connection, input string) (model.Connection, error) {
	if len(c.Targets) != 1 {
		return c, errors.New("use the form or managed JSON for multiple firewall destinations")
	}
	pattern := iptablesNative
	if c.Engine == "nftables" {
		pattern = nftNative
	}
	matches := pattern.FindAllStringSubmatch(input, -1)
	if len(matches) < 1 || len(matches) > 2 {
		return c, errors.New("keep the generated single-destination DNAT structure")
	}
	first := matches[0]
	c.Bind, c.Interface, c.Protocol, c.Ports = first[1], first[2], first[3], first[4]
	if c.Interface == "" {
		c.Interface = "any"
	}
	if len(matches) == 2 {
		if first[3] == matches[1][3] {
			return c, errors.New("duplicate traffic protocol")
		}
		c.Protocol = "both"
	}
	host, port, e := net.SplitHostPort(first[5])
	if e != nil {
		return c, e
	}
	p, e := strconv.Atoi(port)
	if e != nil {
		return c, e
	}
	c.Targets = []model.Target{{IP: host, Port: p, Weight: c.Targets[0].Weight}}
	c.SNAT = "preserve"
	if strings.Contains(input, "masquerade") || strings.Contains(input, "MASQUERADE") {
		c.SNAT = "masquerade"
	}
	return c, nil
}
