package health

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Prober checks one target. Implementations must honor ctx and stay bounded.
type Prober interface {
	Probe(ctx context.Context, t Target) Result
}

// NetProber opens one TCP connection (closed at once, before any payload)
// or sends one ICMP echo. ICMP needs a raw socket, which the root broker has.
type NetProber struct{ Timeout time.Duration }

func (p NetProber) timeout() time.Duration {
	if p.Timeout <= 0 {
		return 3 * time.Second
	}
	return p.Timeout
}

func (p NetProber) Probe(ctx context.Context, t Target) Result {
	address, e := netip.ParseAddr(t.Address)
	if e != nil || address.Zone() != "" {
		return Result{Error: "invalid address"}
	}
	ctx, cancel := context.WithTimeout(ctx, p.timeout())
	defer cancel()
	switch t.Kind {
	case KindTCP:
		if t.Port < 1 || t.Port > 65535 {
			return Result{Error: "invalid port"}
		}
		return tcpProbe(ctx, netip.AddrPortFrom(address.Unmap(), uint16(t.Port)))
	case KindICMP:
		return icmpProbe(ctx, address.Unmap())
	}
	return Result{Error: "unsupported probe"}
}

func tcpProbe(ctx context.Context, address netip.AddrPort) Result {
	start := time.Now()
	conn, e := (&net.Dialer{}).DialContext(ctx, "tcp", address.String())
	if e != nil {
		return Result{Error: classify(e)}
	}
	rtt := time.Since(start)
	_ = conn.Close()
	return Result{OK: true, RTT: float64(rtt.Microseconds()) / 1000}
}

// classify maps network errors to short stable reasons for the interface.
func classify(e error) string {
	switch {
	case errors.Is(e, context.DeadlineExceeded), errors.Is(e, os.ErrDeadlineExceeded):
		return "timeout"
	case errors.Is(e, syscall.ECONNREFUSED):
		return "refused"
	case errors.Is(e, syscall.EHOSTUNREACH), errors.Is(e, syscall.ENETUNREACH):
		return "unreachable"
	case errors.Is(e, syscall.EPERM), errors.Is(e, syscall.EACCES):
		return "blocked"
	}
	var t interface{ Timeout() bool }
	if errors.As(e, &t) && t.Timeout() {
		return "timeout"
	}
	// Other platforms (development builds) report these only as text.
	text := e.Error()
	switch {
	case strings.Contains(text, "refused"):
		return "refused"
	case strings.Contains(text, "unreachable"):
		return "unreachable"
	}
	return "error"
}

func icmpProbe(ctx context.Context, address netip.Addr) Result {
	network, request, reply := "ip4:icmp", byte(8), byte(0)
	if address.Is6() {
		network, request, reply = "ip6:ipv6-icmp", 128, 129
	}
	conn, e := net.ListenPacket(network, "")
	if e != nil {
		return Result{Error: "icmp unavailable"}
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.SetDeadline(time.Now()) })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	}
	id, seq := uint16(rand.Uint32()), uint16(rand.Uint32())
	message := []byte{request, 0, 0, 0, byte(id >> 8), byte(id), byte(seq >> 8), byte(seq), 'g', 't', 'm', '-', 'p', 'r', 'b', 0}
	if !address.Is6() {
		// The kernel fills the ICMPv6 checksum; IPv4 needs it here.
		sum := checksum(message)
		message[2], message[3] = byte(sum>>8), byte(sum)
	}
	start := time.Now()
	if _, e = conn.WriteTo(message, &net.IPAddr{IP: address.AsSlice()}); e != nil {
		return Result{Error: classify(e)}
	}
	buffer := make([]byte, 1500)
	for {
		n, from, e := conn.ReadFrom(buffer)
		if e != nil {
			return Result{Error: classify(e)}
		}
		source, ok := from.(*net.IPAddr)
		if !ok || n < 8 {
			continue
		}
		got, ok := netip.AddrFromSlice(source.IP)
		if !ok || got.Unmap() != address || buffer[0] != reply {
			continue
		}
		if uint16(buffer[4])<<8|uint16(buffer[5]) != id || uint16(buffer[6])<<8|uint16(buffer[7]) != seq {
			continue
		}
		return Result{OK: true, RTT: float64(time.Since(start).Microseconds()) / 1000}
	}
}

func checksum(b []byte) uint16 {
	sum := uint32(0)
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(b[i])<<8 | uint32(b[i+1])
	}
	if len(b)%2 == 1 {
		sum += uint32(b[len(b)-1]) << 8
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

// Run probes targets with bounded parallelism and returns results by key.
// Service targets are skipped; the caller supplies systemd state for them.
func Run(ctx context.Context, p Prober, targets []Target, parallel int) map[string]Result {
	results := make(map[string]Result, len(targets))
	var mu sync.Mutex
	var wg sync.WaitGroup
	gate := make(chan struct{}, max(1, parallel))
	for _, t := range targets {
		if t.Kind == KindService {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case gate <- struct{}{}:
			case <-ctx.Done():
				mu.Lock()
				results[t.Key] = Result{Error: "timeout"}
				mu.Unlock()
				return
			}
			r := p.Probe(ctx, t)
			<-gate
			if len(r.Error) > 40 {
				r.Error = strings.TrimSpace(r.Error[:40])
			}
			mu.Lock()
			results[t.Key] = r
			mu.Unlock()
		}()
	}
	wg.Wait()
	return results
}
