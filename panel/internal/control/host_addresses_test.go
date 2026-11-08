package control

import (
	"net/netip"
	"slices"
	"strings"
	"testing"
)

func TestDefaultRouteInterface(t *testing.T) {
	table := "Iface\tDestination\tGateway\tFlags\n" +
		"docker0\t000011AC\t00000000\t0001\n" +
		"eth0\t00000000\t01011FAC\t0003\n"
	if got := defaultRouteInterface(strings.NewReader(table)); got != "eth0" {
		t.Fatalf("uplink = %q", got)
	}
	if got := defaultRouteInterface(strings.NewReader("Iface\tDestination\n")); got != "" {
		t.Fatalf("no default route = %q", got)
	}
}

// A Hetzner-like host: docker0 is listed before the uplink's address, and an
// additional IPv4 sits beside the DHCP address on eth0.
func TestOrderHostAddressesPutsTheUplinkFirst(t *testing.T) {
	a := func(iface, ip string) hostAddress { return hostAddress{iface: iface, addr: netip.MustParseAddr(ip)} }
	got := orderHostAddresses([]hostAddress{
		a("lo", "127.0.0.1"), a("docker0", "172.17.0.1"), a("eth0", "2a01:4f8::1"),
		a("eth0", "78.47.250.5"), a("eth0", "192.0.2.99"), a("eth0", "fe80::1"),
		a("gre1", "10.0.1.1"), a("veth12ab", "10.10.0.1"),
	}, "eth0")
	want := []string{"78.47.250.5", "192.0.2.99", "2a01:4f8::1", "10.0.1.1", "172.17.0.1", "10.10.0.1"}
	if !slices.Equal(got, want) {
		t.Fatalf("order = %v, want %v", got, want)
	}
}
