package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestMentionsMatchesWholeAddresses(t *testing.T) {
	text := "addresses: [91.98.109.209/32, 10.0.0.15]\nup ip addr add 203.0.113.4 dev eth0\n"
	for address, want := range map[string]bool{
		"91.98.109.209": true,
		"91.98.109.20":  false, // prefix of another address
		"1.98.109.209":  false, // suffix of another address
		"10.0.0.1":      false,
		"10.0.0.15":     true,
		"203.0.113.4":   true,
		"203.0.113.40":  false,
	} {
		if got := mentions(text, address); got != want {
			t.Errorf("mentions(%s) = %v, want %v", address, got, want)
		}
	}
}

func TestDynamicAddressesReadsLeases(t *testing.T) {
	listing := `2: eth0    inet 2.31.132.208/32 metric 100 scope global dynamic eth0\       valid_lft 86379sec preferred_lft 86379sec
2: eth0    inet 91.98.109.209/32 scope global eth0\       valid_lft forever preferred_lft forever
2: eth0    inet6 2001:db8::5/64 scope global dynamic mngtmpaddr \       valid_lft 86000sec preferred_lft 14000sec`
	got := dynamicAddresses(listing)
	if !got["2.31.132.208"] || !got["2001:db8::5"] || got["91.98.109.209"] {
		t.Fatalf("dynamic = %v", got)
	}
}

func TestMarkTemporaryFlagsHandAddedUplinkAddresses(t *testing.T) {
	host := []HostAddressView{
		{Interface: "eth0", Address: "2.31.132.208", Prefix: 32, Uplink: true},  // DHCP lease
		{Interface: "eth0", Address: "91.98.109.209", Prefix: 32, Uplink: true}, // ip address add
		{Interface: "eth0", Address: "198.51.100.7", Prefix: 32, Uplink: true},  // netplan
		{Interface: "eth0", Address: "203.0.113.40", Prefix: 32, Uplink: true},  // kept by gtm-addr-1
		{Interface: "eth0", Address: "2001:db8::9", Prefix: 64, Uplink: true},   // IPv6: left alone
		{Interface: "gre-tun-1", Address: "10.0.1.2", Prefix: 30},               // not the uplink
		{Interface: "docker0", Address: "172.17.0.1", Prefix: 16, Container: true},
	}
	extra := []ExtraAddress{{ID: 1, Address: "203.0.113.40/32", Interface: "eth0"}}
	markTemporary(host, extra, map[string]bool{"2.31.132.208": true}, "addresses:\n  - 198.51.100.7/32\n")
	for _, h := range host {
		if want := h.Address == "91.98.109.209"; h.Temporary != want {
			t.Errorf("%s temporary = %v, want %v", h.Address, h.Temporary, want)
		}
	}
}

func TestNetworkConfigReadsRegularFilesOnly(t *testing.T) {
	dir := t.TempDir()
	if e := os.WriteFile(filepath.Join(dir, "50-cloud-init.yaml"), []byte("addresses: [198.51.100.7/32]"), 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.Mkdir(filepath.Join(dir, "sub.yaml"), 0700); e != nil {
		t.Fatal(e)
	}
	text := networkConfig([]string{filepath.Join(dir, "*.yaml")})
	if !mentions(text, "198.51.100.7") {
		t.Fatalf("config = %q", text)
	}
}

func TestKeepArgsValidates(t *testing.T) {
	args, e := AddressInput{Address: "91.98.109.209/32", Interface: "eth0", Gateway: "1.2.3.4"}.keepArgs()
	if e != nil || len(args) != 2 || args[0] != "91.98.109.209/32" || args[1] != "eth0" {
		t.Fatalf("args=%v e=%v", args, e)
	}
	for _, bad := range []AddressInput{{Address: "91.98.109.209", Interface: "eth0"}, {Address: "91.98.109.209/32", Interface: "any"}, {Address: "91.98.109.209/32", Interface: "eth0;x"}} {
		if _, e := bad.keepArgs(); e == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}
