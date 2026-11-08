package control

import (
	"bufio"
	"io"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// hostAddress is one usable address of this server and the interface that
// holds it.
type hostAddress struct {
	iface string
	addr  netip.Addr
}

// containerInterface names bridges and veth pairs that container runtimes and
// hypervisors create; their addresses are never what a peer or client uses.
func containerInterface(name string) bool {
	for _, prefix := range []string{"docker", "veth", "br-", "virbr", "cni", "flannel", "cali", "lxc", "lxd"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// defaultRouteInterface reads the IPv4 default route's interface from a
// /proc/net/route table. It returns "" when there is none.
func defaultRouteInterface(r io.Reader) string {
	s := bufio.NewScanner(r)
	for s.Scan() {
		f := strings.Fields(s.Text())
		if len(f) > 2 && f[1] == "00000000" && f[0] != "Iface" {
			return f[0]
		}
	}
	return ""
}

// orderHostAddresses puts the default route's interface first, container
// bridges last and IPv4 before IPv6 within each group, keeping the kernel's
// order otherwise. Loopback and link-local addresses are dropped.
func orderHostAddresses(in []hostAddress, uplink string) []string {
	rank := func(a hostAddress) int {
		switch {
		case a.iface == uplink && uplink != "":
			return 0
		case containerInterface(a.iface):
			return 2
		}
		return 1
	}
	kept := []hostAddress{}
	for _, a := range in {
		if a.addr.IsValid() && !a.addr.IsLoopback() && !a.addr.IsLinkLocalUnicast() {
			kept = append(kept, a)
		}
	}
	sort.SliceStable(kept, func(i, j int) bool {
		if ri, rj := rank(kept[i]), rank(kept[j]); ri != rj {
			return ri < rj
		}
		return kept[i].addr.Is4() && !kept[j].addr.Is4()
	})
	out := make([]string, 0, len(kept))
	for _, a := range kept {
		out = append(out, a.addr.String())
	}
	return out
}

// localAddresses lists this server's addresses, uplink first.
func localAddresses() []string {
	all := []hostAddress{}
	interfaces, e := net.Interfaces()
	if e != nil {
		return []string{}
	}
	for _, i := range interfaces {
		addresses, e := i.Addrs()
		if e != nil {
			continue
		}
		for _, address := range addresses {
			if p, e := netip.ParsePrefix(address.String()); e == nil {
				all = append(all, hostAddress{iface: i.Name, addr: p.Addr().Unmap()})
			}
		}
	}
	uplink := ""
	if f, e := os.Open("/proc/net/route"); e == nil {
		uplink = defaultRouteInterface(f)
		_ = f.Close()
	}
	return orderHostAddresses(all, uplink)
}
