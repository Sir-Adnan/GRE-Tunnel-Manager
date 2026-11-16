package nodes

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

// ReaddressRequest moves the GRE tunnels between two servers after Changed
// got a new public address: Changed rewrites its local end, Peer its remote end.
type ReaddressRequest struct {
	ID      string     `json:"id"`
	Name    string     `json:"name"`
	Changed NodeChoice `json:"changed"`
	Peer    NodeChoice `json:"peer"`
	Old     string     `json:"old"`
	New     string     `json:"new"`
}

// atLeast compares the numeric release part of two x.y.z versions.
func atLeast(version, minimum string) bool {
	parse := func(s string) []int {
		s, _, _ = strings.Cut(s, "-")
		s, _, _ = strings.Cut(s, "+")
		out := []int{}
		for _, p := range strings.Split(s, ".") {
			n, e := strconv.Atoi(p)
			if e != nil {
				return nil
			}
			out = append(out, n)
		}
		return out
	}
	a, b := parse(version), parse(minimum)
	if len(a) != 3 || len(b) != 3 {
		return false
	}
	return slices.Compare(a, b) >= 0
}

// readdressReady checks that a remote Node's Agent runs readdress tasks and,
// for the changed server, that it already reports the new address.
func (h *Hub) readdressReady(c NodeChoice, address string) error {
	if c.ID == "local" {
		return nil
	}
	o := h.cache[c.ID]
	if !atLeast(o.report.Version, control.ReaddressVersion) {
		return problem("agent_outdated", "Update the Agent on this server to "+control.ReaddressVersion+" or later to change addresses from here")
	}
	if address == "" {
		return nil
	}
	var inv control.Inventory
	if json.Unmarshal(o.inventory, &inv) != nil || !slices.Contains(inv.Host.Addresses, address) {
		return problem("address_missing", "The server does not report the new address yet; add it on the server first")
	}
	return nil
}

// CreateReaddress queues a paired job that moves both ends of the tunnels.
func (h *Hub) CreateReaddress(in ReaddressRequest) (PairView, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	existing, inputHash, e := h.replay(in.ID, in, in.Changed, in.Peer)
	if e != nil || existing != nil {
		return deref(existing), e
	}
	if a, e := netip.ParseAddr(in.New); e == nil {
		in.New = a.Unmap().String()
	}
	if e := h.readdressReady(in.Changed, in.New); e != nil {
		return PairView{}, e
	}
	if e := h.readdressReady(in.Peer, ""); e != nil {
		return PairView{}, e
	}
	if in.Name == "" {
		in.Name = "readdress-" + in.ID[:8]
	}
	if !validName(in.Name) {
		return PairView{}, problem("invalid_name", "Use a name with 1–64 visible characters")
	}
	p := pair{Schema: 1, ID: in.ID, Name: in.Name, Kind: "readdress", InputHash: inputHash, Revision: randomID(), State: "preparing", Created: h.now()}
	p.Expires = p.Created.Add(10 * time.Minute)
	change := control.Readdress{Old: in.Old, New: in.New, Use: "local"}
	p.Steps[0] = pairStep{Node: in.Changed.ID, NodeRevision: in.Changed.Revision, Stage: "prepare", Spec: control.NodeSpec{Kind: "readdress", Readdress: change}}
	change.Use = "remote"
	p.Steps[1] = pairStep{Node: in.Peer.ID, NodeRevision: in.Peer.Revision, Stage: "prepare", Spec: control.NodeSpec{Kind: "readdress", Readdress: change}}
	if p.Steps[0].Spec.Validate() != nil {
		return PairView{}, problem("invalid_address", "Enter two different public addresses of the same family")
	}
	return h.queue(p)
}
