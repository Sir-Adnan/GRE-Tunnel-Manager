package control

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// Address tools: where owned resources use an address (address-uses), moving
// them to a new one after an IP change (address-replace) and additional
// addresses kept in owned units (extra-*). The engine does the work; see
// src/addresses.sh.

const addressItemsMax = 64

var addressItem = regexp.MustCompile(`^(all|gre-tun-[0-9]{1,3}|F[0-9]{6}|gtm-(frp|rathole)-(entrance|destination)-[a-zA-Z0-9_-]{1,32})$`)
var interfaceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

// AddressUse is one place an owned resource uses an address: Use is local
// (an address of this server) or remote (another server's).
type AddressUse struct {
	Use     string `json:"use"`
	Address string `json:"address"`
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	Name    string `json:"name"`
	// Present: a local address is still on this server.
	Present bool `json:"present"`
	// Editable is false for uses this tool cannot move (WSS gateways).
	Editable bool `json:"editable"`
}

// HostAddressView is one address of this server and its interface.
type HostAddressView struct {
	Interface string `json:"interface"`
	Address   string `json:"address"`
	Prefix    int    `json:"prefix"`
	Uplink    bool   `json:"uplink"`
	Container bool   `json:"container"`
	// Temporary: an IPv4 address on the uplink that no network configuration
	// or owned unit sets (added by hand), so the next restart drops it.
	Temporary bool `json:"temporary"`
}

// ExtraAddress is an additional address kept by a gtm-addr-N unit.
type ExtraAddress struct {
	ID        int    `json:"id"`
	Address   string `json:"address"`
	Interface string `json:"interface"`
	Gateway   string `json:"gateway,omitempty"`
	Active    bool   `json:"active"`
	Present   bool   `json:"present"`
}

// AddressReport is the IP tools page: this server's addresses, every use and
// the local addresses in use that are no longer on the server (Stale).
type AddressReport struct {
	Addresses  []HostAddressView `json:"addresses"`
	Uplink     string            `json:"uplink"`
	Gateway    string            `json:"gateway"`
	Interfaces []string          `json:"interfaces"`
	Uses       []AddressUse      `json:"uses"`
	Stale      []string          `json:"stale"`
	// Suggested is the likely new address for the first stale one.
	Suggested string         `json:"suggested"`
	Extra     []ExtraAddress `json:"extra"`
}

// AddressInput carries one address change or one additional address.
type AddressInput struct {
	Old   string   `json:"old,omitempty"`
	New   string   `json:"new,omitempty"`
	Use   string   `json:"use,omitempty"`
	Items []string `json:"items,omitempty"`
	// Additional address: Address is ADDRESS/PREFIX; Gateway is optional.
	Address   string `json:"address,omitempty"`
	Interface string `json:"interface,omitempty"`
	Gateway   string `json:"gateway,omitempty"`
	ID        int    `json:"id,omitempty"`
}

func usableAddress(a netip.Addr) bool {
	return a.IsValid() && a.Zone() == "" && !a.Is4In6() && !a.IsUnspecified() && !a.IsLoopback() && !a.IsMulticast() && !a.IsLinkLocalUnicast()
}

// replaceArgs validates an address change: OLD NEW USE ITEM...
func (in AddressInput) replaceArgs() ([]string, error) {
	old, e := netip.ParseAddr(in.Old)
	next, f := netip.ParseAddr(in.New)
	if e != nil || f != nil || !usableAddress(old) || !usableAddress(next) {
		return nil, errors.New("enter the old and the new address")
	}
	if old.Is4() != next.Is4() {
		return nil, errors.New("both addresses must be IPv4, or both IPv6")
	}
	if old == next {
		return nil, errors.New("the new address is the same as the old one")
	}
	if !oneOf(in.Use, "local", "remote") {
		return nil, errors.New("choose whose address changed")
	}
	if len(in.Items) < 1 || len(in.Items) > addressItemsMax {
		return nil, errors.New("choose what to change")
	}
	args := []string{old.String(), next.String(), in.Use}
	for _, item := range in.Items {
		if !addressItem.MatchString(item) {
			return nil, errors.New("unknown item: " + item)
		}
		args = append(args, item)
	}
	return args, nil
}

// extraArgs validates an additional address: ADDRESS/PREFIX IFACE GATEWAY|-.
func (in AddressInput) extraArgs() ([]string, error) {
	p, e := netip.ParsePrefix(in.Address)
	if e != nil || !usableAddress(p.Addr()) || p.Bits() < 8 {
		return nil, errors.New("enter the address with its prefix, like 203.0.113.40/32")
	}
	if !interfaceName.MatchString(in.Interface) || in.Interface == "any" {
		return nil, errors.New("choose a network interface")
	}
	gateway := "-"
	if in.Gateway != "" {
		g, e := netip.ParseAddr(in.Gateway)
		if e != nil || !g.IsValid() || g.Zone() != "" || g.IsUnspecified() || g.Is4() != p.Addr().Is4() {
			return nil, errors.New("the gateway must be an address of the same family")
		}
		gateway = g.String()
	}
	return []string{p.String(), in.Interface, gateway}, nil
}

// keepArgs validates an address to keep across restarts: ADDRESS/PREFIX IFACE.
func (in AddressInput) keepArgs() ([]string, error) {
	in.Gateway = ""
	args, e := in.extraArgs()
	if e != nil {
		return nil, e
	}
	return args[:2], nil
}

// Network configuration that sets addresses at boot: netplan (and what it
// generates), ifupdown, systemd-networkd and NetworkManager.
var networkConfigGlobs = []string{
	"/etc/netplan/*.yaml", "/etc/netplan/*.yml", "/etc/network/interfaces", "/etc/network/interfaces.d/*",
	"/etc/systemd/network/*.network", "/run/systemd/network/*.network", "/etc/NetworkManager/system-connections/*",
}

// networkConfig concatenates the network configuration, bounded in size.
func networkConfig(globs []string) string {
	var b strings.Builder
	for _, g := range globs {
		paths, _ := filepath.Glob(g)
		for _, p := range paths {
			if info, e := os.Stat(p); e != nil || !info.Mode().IsRegular() || info.Size() > 256<<10 || b.Len() > 2<<20 {
				continue
			}
			if data, e := os.ReadFile(p); e == nil {
				b.Write(data)
				b.WriteByte('\n')
			}
		}
	}
	return b.String()
}

// dynamicAddresses lists addresses a DHCP or router advertisement lease keeps
// ("dynamic" in "ip -o address show").
func dynamicAddresses(listing string) map[string]bool {
	out := map[string]bool{}
	for _, line := range strings.Split(listing, "\n") {
		f := strings.Fields(line)
		for i := 0; i+1 < len(f); i++ {
			if (f[i] == "inet" || f[i] == "inet6") && slices.Contains(f, "dynamic") {
				if p, e := netip.ParsePrefix(f[i+1]); e == nil {
					out[p.Addr().String()] = true
				}
			}
		}
	}
	return out
}

// mentions reports whether text names the IPv4 address as a whole token.
func mentions(text, address string) bool {
	for i := 0; ; {
		j := strings.Index(text[i:], address)
		if j < 0 {
			return false
		}
		j += i
		end := j + len(address)
		before := j == 0 || !strings.ContainsRune("0123456789.", rune(text[j-1]))
		after := end == len(text) || !strings.ContainsRune("0123456789", rune(text[end])) && !(text[end] == '.' && end+1 < len(text) && text[end+1] >= '0' && text[end+1] <= '9')
		if before && after {
			return true
		}
		i = j + 1
	}
}

// markTemporary flags IPv4 addresses on the uplink that nothing re-creates at
// boot: not leased (dynamic), not in the network configuration and not kept
// by an owned unit. IPv6 is left alone; its spellings in files vary.
func markTemporary(host []HostAddressView, extra []ExtraAddress, dynamic map[string]bool, config string) {
	kept := map[string]bool{}
	for _, x := range extra {
		kept[strings.SplitN(x.Address, "/", 2)[0]] = true
	}
	for i := range host {
		h := &host[i]
		a, e := netip.ParseAddr(h.Address)
		if e != nil || !a.Is4() || !h.Uplink || h.Container || dynamic[h.Address] || kept[h.Address] || mentions(config, h.Address) {
			continue
		}
		h.Temporary = true
	}
}

// parseAddressUses reads address-uses rows; malformed rows are skipped.
func parseAddressUses(out string, names map[string]string) []AddressUse {
	uses := []AddressUse{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 6 || !oneOf(f[0], "local", "remote") || !oneOf(f[2], "gre", "connection", "reverse") || !addressItem.MatchString(f[3]) || f[3] == "all" {
			continue
		}
		a, e := netip.ParseAddr(f[1])
		if e != nil {
			continue
		}
		u := AddressUse{Use: f[0], Address: a.String(), Kind: f[2], ID: f[3], Name: names[f[3]], Present: f[4] == "1", Editable: f[5] == "1"}
		if u.Name == "" {
			u.Name = f[3]
			if strings.HasPrefix(f[3], "gre-tun-") {
				u.Name = "GRE " + strings.TrimPrefix(f[3], "gre-tun-")
			}
		}
		uses = append(uses, u)
	}
	return uses
}

// parseExtraAddresses reads extra-list rows: N ADDRESS/PREFIX IFACE GATEWAY ACTIVE PRESENT.
func parseExtraAddresses(out string) []ExtraAddress {
	extra := []ExtraAddress{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 6 {
			continue
		}
		id, e := strconv.Atoi(f[0])
		p, g := netip.ParsePrefix(f[1])
		if e != nil || g != nil || id < 1 || id > 32 || !interfaceName.MatchString(f[2]) {
			continue
		}
		x := ExtraAddress{ID: id, Address: p.String(), Interface: f[2], Active: f[4] == "1", Present: f[5] == "1"}
		if gw, e := netip.ParseAddr(f[3]); e == nil {
			x.Gateway = gw.String()
		}
		extra = append(extra, x)
	}
	return extra
}

// addressReport lists stale local addresses (in use, no longer on the server)
// and suggests the uplink's first address of the same family as the new one.
func addressReport(uses []AddressUse, extra []ExtraAddress, host []HostAddressView, uplink, gateway string, interfaces []string) AddressReport {
	r := AddressReport{Addresses: host, Uplink: uplink, Gateway: gateway, Interfaces: interfaces, Uses: uses, Stale: []string{}, Extra: extra}
	seen := map[string]bool{}
	for _, u := range uses {
		if u.Use == "local" && !u.Present && !seen[u.Address] {
			seen[u.Address] = true
			r.Stale = append(r.Stale, u.Address)
		}
	}
	if len(r.Stale) > 0 {
		v4 := strings.Contains(r.Stale[0], ".")
		for _, h := range host {
			if !h.Container && strings.Contains(h.Address, ".") == v4 {
				r.Suggested = h.Address
				break
			}
		}
	}
	return r
}

// defaultGateway reads the IPv4 default gateway of iface from /proc/net/route.
func defaultGateway(r io.Reader, iface string) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) < 3 || f[1] != "00000000" || f[0] != iface {
			continue
		}
		b, e := hex.DecodeString(f[2])
		if e != nil || len(b) != 4 {
			return ""
		}
		var a [4]byte
		binary.BigEndian.PutUint32(a[:], binary.LittleEndian.Uint32(b))
		if g := netip.AddrFrom4(a); !g.IsUnspecified() {
			return g.String()
		}
	}
	return ""
}

// hostAddressViews lists this server's addresses with interface and prefix in
// the same order as localAddresses, plus the interfaces an address can go on.
func hostAddressViews() ([]HostAddressView, string, string, []string) {
	all := []hostAddress{}
	names := []string{}
	interfaces, e := net.Interfaces()
	if e != nil {
		return []HostAddressView{}, "", "", names
	}
	for _, i := range interfaces {
		if i.Flags&net.FlagLoopback == 0 && !containerInterface(i.Name) && interfaceName.MatchString(i.Name) {
			names = append(names, i.Name)
		}
		addresses, e := i.Addrs()
		if e != nil {
			continue
		}
		for _, address := range addresses {
			if p, e := netip.ParsePrefix(address.String()); e == nil {
				all = append(all, hostAddress{iface: i.Name, addr: p.Addr().Unmap(), bits: p.Bits()})
			}
		}
	}
	uplink, gateway := "", ""
	if data, e := os.ReadFile("/proc/net/route"); e == nil {
		uplink = defaultRouteInterface(strings.NewReader(string(data)))
		gateway = defaultGateway(strings.NewReader(string(data)), uplink)
	}
	views := []HostAddressView{}
	for _, a := range sortHostAddresses(all, uplink) {
		views = append(views, HostAddressView{Interface: a.iface, Address: a.addr.String(), Prefix: a.bits, Uplink: a.iface == uplink && uplink != "", Container: containerInterface(a.iface)})
	}
	return views, uplink, gateway, names
}

// addresses serves the IP tools report and its three write operations.
func (m *Manager) addresses(ctx context.Context, r Request) (any, error) {
	switch r.Action {
	case "addresses":
		inventory, e := m.Inventory(ctx)
		if e != nil {
			return nil, e
		}
		names := map[string]string{}
		for _, c := range inventory.Connections {
			names[c.ID] = c.Name
		}
		for _, res := range inventory.Resources {
			if res.Name != res.ID {
				names[res.ID] = res.Name
			}
		}
		out, e := m.call(ctx, "address-uses", "")
		if e != nil {
			return nil, e
		}
		extra, e := m.call(ctx, "extra-list", "")
		if e != nil {
			return nil, e
		}
		host, uplink, gateway, interfaces := hostAddressViews()
		kept := parseExtraAddresses(extra)
		if uplink != "" && interfaceName.MatchString(uplink) {
			listing, e := exec.CommandContext(ctx, "ip", "-o", "address", "show", "dev", uplink).Output()
			if e == nil {
				markTemporary(host, kept, dynamicAddresses(string(listing)), networkConfig(networkConfigGlobs))
			}
		}
		return addressReport(parseAddressUses(out, names), kept, host, uplink, gateway, interfaces), nil
	case "address-extra-keep":
		args, e := r.Address.keepArgs()
		if e != nil {
			return nil, e
		}
		return m.call(ctx, "extra-keep", "", args...)
	case "address-replace":
		args, e := r.Address.replaceArgs()
		if e != nil {
			return nil, e
		}
		return m.call(ctx, "address-replace", "", args...)
	case "address-extra-add":
		args, e := r.Address.extraArgs()
		if e != nil {
			return nil, e
		}
		return m.call(ctx, "extra-add", "", args...)
	case "address-extra-delete":
		if r.Address.ID < 1 || r.Address.ID > 32 {
			return nil, errors.New("choose an additional address")
		}
		return m.call(ctx, "extra-delete", "", strconv.Itoa(r.Address.ID))
	}
	return nil, errors.New("unknown address action")
}
