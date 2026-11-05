package health

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// MTUResult is the outcome of an on-demand path MTU test through a tunnel.
type MTUResult struct {
	Address string `json:"address"`
	// Interface is the local link MTU; Path is the largest IPv4 packet with
	// the Don't Fragment bit that got an echo reply (0 when none did).
	Interface int   `json:"interface_mtu"`
	Path      int   `json:"path_mtu"`
	Probes    int   `json:"probes"`
	Failed    []int `json:"failed,omitempty"`
	Duration  int64 `json:"duration_ms"`
}

const (
	minMTU = 1200
	// mtuProbes bounds the test: a binary search plus one retry per size.
	mtuProbes = 24
)

// echoSender sends one ICMP echo of the given total IPv4 packet size with
// the Don't Fragment bit set and reports whether a reply arrived.
type echoSender interface {
	Echo(ctx context.Context, size int) (bool, error)
	Close() error
}

// PathMTU searches the largest packet in [1200, link] that crosses to the
// peer unfragmented. It sends at most 24 small bursts and runs only on
// request. A size counts as failed after two silent attempts.
func PathMTU(ctx context.Context, address netip.Addr, link int) (MTUResult, error) {
	if !address.Is4() {
		return MTUResult{}, errors.New("the MTU test supports IPv4 tunnel peers")
	}
	if link < minMTU || link > 9000 {
		return MTUResult{}, errors.New("interface MTU out of range")
	}
	sender, e := newEchoSender(address)
	if e != nil {
		return MTUResult{}, e
	}
	defer sender.Close()
	return searchMTU(ctx, sender, address, link)
}

func searchMTU(ctx context.Context, sender echoSender, address netip.Addr, link int) (MTUResult, error) {
	start := time.Now()
	r := MTUResult{Address: address.String(), Interface: link}
	try := func(size int) (bool, error) {
		for attempt := 0; attempt < 2 && r.Probes < mtuProbes; attempt++ {
			r.Probes++
			ok, e := sender.Echo(ctx, size)
			if e != nil || ok {
				return ok, e
			}
		}
		r.Failed = append(r.Failed, size)
		return false, nil
	}
	path, e := func() (int, error) {
		// The smallest size must pass, or the peer does not answer at all.
		if ok, e := try(minMTU); e != nil || !ok {
			return 0, e
		}
		if ok, e := try(link); e != nil || ok {
			return link, e
		}
		low, high := minMTU, link
		for high-low > 1 && r.Probes < mtuProbes {
			mid := (low + high) / 2
			ok, e := try(mid)
			if e != nil {
				return low, e
			}
			if ok {
				low = mid
			} else {
				high = mid
			}
		}
		return low, nil
	}()
	r.Path, r.Duration = path, time.Since(start).Milliseconds()
	return r, e
}
