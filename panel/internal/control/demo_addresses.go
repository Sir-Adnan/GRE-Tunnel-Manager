package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// demoAddressState models an entry server that its datacenter moved from
// 203.0.113.5 to 203.0.113.10: one GRE tunnel still uses the old address.
type demoAddressState struct {
	gre   map[string][2]string // id → local, remote
	extra []ExtraAddress
}

const demoTemporaryAddress = "203.0.113.44"

func (d *Demo) addressState() *demoAddressState {
	x := d.extras()
	if x.addresses == nil {
		x.addresses = &demoAddressState{gre: map[string][2]string{"gre-tun-7": {"203.0.113.5", "198.51.100.70"}}, extra: []ExtraAddress{}}
	}
	return x.addresses
}

func (d *Demo) demoHostAddresses() []HostAddressView {
	host := []HostAddressView{
		{Interface: "eth0", Address: "203.0.113.10", Prefix: 24, Uplink: true},
		{Interface: "eth0", Address: "2001:db8::10", Prefix: 64, Uplink: true},
	}
	state := d.addressState()
	kept := map[string]bool{}
	for _, x := range state.extra {
		p := netip.MustParsePrefix(x.Address)
		kept[p.Addr().String()] = true
		host = append(host, HostAddressView{Interface: x.Interface, Address: p.Addr().String(), Prefix: p.Bits(), Uplink: x.Interface == "eth0"})
	}
	// One address was added by hand with "ip address add": a restart drops it.
	if !kept[demoTemporaryAddress] {
		host = append(host, HostAddressView{Interface: "eth0", Address: demoTemporaryAddress, Prefix: 32, Uplink: true, Temporary: true})
	}
	return append(host, HostAddressView{Interface: "docker0", Address: "172.17.0.1", Prefix: 16, Container: true})
}

// demoTunnels gives every simulated GRE tunnel a local and a remote address.
func (d *Demo) demoTunnels() ([]string, map[string][2]string) {
	state := d.addressState()
	ids, out := []string{}, map[string][2]string{}
	for _, r := range demoResources(d.inventory).Resources {
		if r.Engine != "gre" {
			continue
		}
		ends, ok := state.gre[r.ID]
		if !ok {
			var g GRE
			if json.Unmarshal([]byte(d.configs[r.ID]), &g) == nil && g.Bind != "" {
				ends = [2]string{g.Bind, g.Remote}
			} else {
				ends = [2]string{"203.0.113.10", "198.51.100.9"}
			}
		}
		ids = append(ids, r.ID)
		out[r.ID] = ends
	}
	return ids, out
}

// withTunnelEnds is the inventory with GRE public ends, as Manager.Inventory
// reads them. Until a GRE is created it shows the simulated GRE 7 that the
// health, traffic and IP pages already use; that one still has the old address.
func (d *Demo) withTunnelEnds() Inventory {
	out := demoResources(d.inventory)
	out.Resources = slices.Clone(out.Resources)
	_, tunnels := d.demoTunnels()
	for i, r := range out.Resources {
		if ends, ok := tunnels[r.ID]; ok {
			out.Resources[i].Bind, out.Resources[i].Remote = ends[0], ends[1]
		}
	}
	return out
}

func (d *Demo) demoAddressUses() []AddressUse {
	present := map[string]bool{}
	for _, h := range d.demoHostAddresses() {
		present[h.Address] = true
	}
	names := map[string]string{}
	for _, r := range demoResources(d.inventory).Resources {
		names[r.ID] = r.Name
	}
	uses := []AddressUse{}
	ids, tunnels := d.demoTunnels()
	for _, id := range ids {
		ends := tunnels[id]
		uses = append(uses, AddressUse{Use: "local", Address: ends[0], Kind: "gre", ID: id, Name: names[id], Present: present[ends[0]], Editable: true})
		uses = append(uses, AddressUse{Use: "remote", Address: ends[1], Kind: "gre", ID: id, Name: names[id], Editable: true})
	}
	for _, c := range d.inventory.Connections {
		if c.Bind != "0.0.0.0" && c.Bind != "::" {
			uses = append(uses, AddressUse{Use: "local", Address: c.Bind, Kind: "connection", ID: c.ID, Name: c.Name, Present: present[c.Bind], Editable: true})
		}
		seen := map[string]bool{}
		for _, t := range c.Targets {
			if a, e := netip.ParseAddr(t.IP); e == nil && !seen[a.String()] {
				seen[a.String()] = true
				uses = append(uses, AddressUse{Use: "remote", Address: a.String(), Kind: "connection", ID: c.ID, Name: c.Name, Editable: true})
			}
		}
	}
	return uses
}

func (d *Demo) addressesDemo(r Request) (json.RawMessage, error) {
	state := d.addressState()
	switch r.Action {
	case "addresses":
		return json.Marshal(addressReport(d.demoAddressUses(), slices.Clone(state.extra), d.demoHostAddresses(), "eth0", "203.0.113.1", []string{"eth0", "eth1"}))
	case "address-replace":
		args, e := r.Address.replaceArgs()
		if e != nil {
			return nil, e
		}
		old, next, use, items := args[0], args[1], args[2], args[3:]
		if use == "local" && !slices.ContainsFunc(d.demoHostAddresses(), func(h HostAddressView) bool { return h.Address == next }) {
			return nil, errors.New("the new address is not on this server: " + next)
		}
		chosen := []AddressUse{}
		for _, item := range items {
			found := false
			for _, u := range d.demoAddressUses() {
				if u.Use == use && u.Address == old && (item == "all" || item == u.ID) {
					found = true
					if !slices.ContainsFunc(chosen, func(c AddressUse) bool { return c.ID == u.ID }) {
						chosen = append(chosen, u)
					}
				}
			}
			if !found {
				return nil, fmt.Errorf("%s does not use %s", item, old)
			}
		}
		_, tunnels := d.demoTunnels()
		lines := []string{}
		for _, u := range chosen {
			switch u.Kind {
			case "gre":
				ends := tunnels[u.ID]
				if use == "local" {
					ends[0] = next
				} else {
					ends[1] = next
				}
				state.gre[u.ID] = ends
			case "connection":
				for i := range d.inventory.Connections {
					c := &d.inventory.Connections[i]
					if c.ID != u.ID {
						continue
					}
					if use == "local" {
						c.Bind = next
					} else {
						for j := range c.Targets {
							if c.Targets[j].IP == old {
								c.Targets[j].IP = next
							}
						}
					}
					if rows, e := c.Rows(c.ID); e == nil {
						c.Revision = model.Revision(rows[0])
					}
				}
			}
			lines = append(lines, "result\t"+u.ID+"\tdone")
		}
		return json.Marshal("Demo: no server settings were changed.\n" + strings.Join(lines, "\n"))
	case "address-extra-add":
		args, e := r.Address.extraArgs()
		if e != nil {
			return nil, e
		}
		address := strings.SplitN(args[0], "/", 2)[0]
		if slices.ContainsFunc(d.demoHostAddresses(), func(h HostAddressView) bool { return h.Address == address }) {
			return nil, errors.New("the address is already on this server: " + address)
		}
		id := 1
		for slices.ContainsFunc(state.extra, func(x ExtraAddress) bool { return x.ID == id }) {
			id++
		}
		if id > 32 {
			return nil, errors.New("at most 32 additional addresses are managed")
		}
		x := ExtraAddress{ID: id, Address: args[0], Interface: args[1], Active: true, Present: true}
		if args[2] != "-" {
			x.Gateway = args[2]
		}
		state.extra = append(state.extra, x)
		return json.Marshal(fmt.Sprintf("extra\t%d\ncheck\tpresent\t1\ncheck\troute\t1", id))
	case "address-extra-keep":
		args, e := r.Address.keepArgs()
		if e != nil {
			return nil, e
		}
		if !slices.ContainsFunc(d.demoHostAddresses(), func(h HostAddressView) bool {
			return h.Temporary && fmt.Sprintf("%s/%d", h.Address, h.Prefix) == args[0] && h.Interface == args[1]
		}) {
			return nil, errors.New("the address is not on " + args[1] + ": " + args[0])
		}
		id := 1
		for slices.ContainsFunc(state.extra, func(x ExtraAddress) bool { return x.ID == id }) {
			id++
		}
		state.extra = append(state.extra, ExtraAddress{ID: id, Address: args[0], Interface: args[1], Active: true, Present: true})
		return json.Marshal(fmt.Sprintf("extra\t%d\ncheck\tpresent\t1\ncheck\troute\t1", id))
	case "address-extra-delete":
		i := slices.IndexFunc(state.extra, func(x ExtraAddress) bool { return x.ID == r.Address.ID })
		if i < 0 {
			return nil, errors.New("choose an additional address")
		}
		address := strings.SplitN(state.extra[i].Address, "/", 2)[0]
		for _, u := range d.demoAddressUses() {
			if u.Use == "local" && u.Address == address {
				return nil, fmt.Errorf("%s still uses %s; change it first", u.ID, address)
			}
		}
		state.extra = slices.Delete(state.extra, i, i+1)
		return json.Marshal("Demo: additional address removed.")
	}
	return nil, errors.New("unknown address action")
}
