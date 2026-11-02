package control

import (
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func TestKernelNativeAcceptsAllLocalAddressEntrances(t *testing.T) {
	base := model.Connection{Engine: "nftables", Targets: []model.Target{{IP: "203.0.113.20", Port: 443, Weight: 1}}}
	cases := []struct {
		engine, text, bind, iface string
	}{
		{"nftables", `add rule inet gre_manager pre meta nfproto ipv4 fib daddr type local tcp dport 443 counter dnat ip to 203.0.113.20:8443 comment "gtm-F000001"`, "0.0.0.0", "any"},
		{"nftables", `add rule inet gre_manager pre meta nfproto ipv6 fib daddr type local iifname "eth1" tcp dport 443 counter dnat ip6 to [2001:db8::20]:8443 comment "gtm-F000001"`, "::", "eth1"},
		{"iptables", "-A GTM_PRE -m addrtype --dst-type LOCAL -i eth1 -p tcp --dport 443 -m comment --comment gtm-F000001 -j DNAT --to-destination 203.0.113.20:8443", "0.0.0.0", "eth1"},
		{"iptables", "-A GTM_PRE -d 192.0.2.10 -p tcp --dport 443 -m comment --comment gtm-F000001 -j DNAT --to-destination 203.0.113.20:8443", "192.0.2.10", "any"},
	}
	for _, item := range cases {
		c := base
		c.Engine = item.engine
		got, e := importKernelNative(c, item.text+"\n")
		if e != nil || got.Bind != item.bind || got.Interface != item.iface || got.Ports != "443" || got.Targets[0].Port != 8443 {
			t.Fatal(item.text, got, e)
		}
	}
}
