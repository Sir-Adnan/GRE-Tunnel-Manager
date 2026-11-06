package control

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"regexp"
	"strconv"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// FlowCounts are new connections per destination of one nftables forward,
// counted in the kernel since its rules were last applied.
type FlowCounts struct {
	Owner        string   `json:"owner"`
	Total        uint64   `json:"total"`
	Destinations []uint64 `json:"destinations"`
	Time         string   `json:"time"`
}

var balanceChain = regexp.MustCompile(`^b_(F[0-9]{6})_(tcp|udp)_([0-9]{1,2})$`)

type nftListing struct {
	Nftables []struct {
		Rule *struct {
			Chain   string            `json:"chain"`
			Comment string            `json:"comment"`
			Expr    []json.RawMessage `json:"expr"`
		} `json:"rule"`
	} `json:"nftables"`
}

func ruleCounter(expr []json.RawMessage) (uint64, bool) {
	for _, raw := range expr {
		var x struct {
			Counter *struct {
				Packets uint64 `json:"packets"`
			} `json:"counter"`
		}
		if json.Unmarshal(raw, &x) == nil && x.Counter != nil {
			return x.Counter.Packets, true
		}
	}
	return 0, false
}

// parseFlowCounts reads the owned table listing. Balancing chains see each
// flow's first packet only (they hang off the NAT hook), so their counters
// are new connections; the entrance rule counts them all.
func parseFlowCounts(id string, destinations int, data []byte) (FlowCounts, error) {
	var listing nftListing
	if e := json.Unmarshal(data, &listing); e != nil {
		return FlowCounts{}, e
	}
	c := FlowCounts{Owner: id, Destinations: make([]uint64, destinations), Time: time.Now().UTC().Format(time.RFC3339)}
	for _, item := range listing.Nftables {
		r := item.Rule
		if r == nil {
			continue
		}
		packets, ok := ruleCounter(r.Expr)
		if !ok {
			continue
		}
		if m := balanceChain.FindStringSubmatch(r.Chain); m != nil && m[1] == id {
			if index, _ := strconv.Atoi(m[3]); index < destinations {
				c.Destinations[index] += packets
			}
			continue
		}
		if r.Chain == "pre" && r.Comment == "gtm-"+id {
			c.Total += packets
		}
	}
	if destinations == 1 {
		c.Destinations[0] = c.Total
	}
	return c, nil
}

func (m *Manager) flowCounts(ctx context.Context, id string) (FlowCounts, error) {
	if !model.IDPattern.MatchString(id) {
		return FlowCounts{}, errors.New("invalid connection ID")
	}
	connections, _, e := m.state(ctx)
	if e != nil {
		return FlowCounts{}, e
	}
	m.fillResolved(ctx, connections)
	for _, c := range connections {
		if c.ID != id {
			continue
		}
		if c.Engine != "nftables" || !c.Enabled {
			return FlowCounts{}, errors.New("flow counts are available for enabled nftables forwards")
		}
		out, e := m.Runner.Run(ctx, "nft", []string{"-j", "list", "table", "inet", "gre_manager"}, "")
		if e != nil {
			return FlowCounts{}, errors.New("cannot read the owned nftables table")
		}
		targets := effectiveTargets(c)
		if len(targets) == 0 {
			return FlowCounts{}, errors.New("resolved destinations are unavailable; refresh inventory")
		}
		return parseFlowCounts(id, len(targets), []byte(out))
	}
	return FlowCounts{}, errors.New("connection not found")
}

// pathMTU tests one GRE link on request: largest unfragmented packet to the
// peer's inner address, compared with the local interface MTU.
func (m *Manager) pathMTU(ctx context.Context, id string) (health.MTUResult, error) {
	if !greID.MatchString(id) || !ServiceOK(id) {
		return health.MTUResult{}, errors.New("invalid GRE ID")
	}
	inventory, e := m.Inventory(ctx)
	if e != nil {
		return health.MTUResult{}, e
	}
	for _, r := range inventory.Resources {
		if r.ID != id {
			continue
		}
		peer, e := netip.ParseAddr(r.Peer)
		if e != nil {
			return health.MTUResult{}, errors.New("the tunnel has no inner peer address")
		}
		link, e := net.InterfaceByName(r.Interface)
		if e != nil {
			return health.MTUResult{}, errors.New("the tunnel interface is not up")
		}
		ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
		return health.PathMTU(ctx, peer, link.MTU)
	}
	return health.MTUResult{}, errors.New("GRE link not found")
}
