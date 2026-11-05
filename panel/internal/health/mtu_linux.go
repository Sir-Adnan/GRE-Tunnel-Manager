//go:build linux

package health

import (
	"context"
	"errors"
	"math/rand/v2"
	"net"
	"net/netip"
	"syscall"
	"time"
)

type rawEcho struct {
	conn    *net.IPConn
	address netip.Addr
	id      uint16
	seq     uint16
}

// newEchoSender opens a raw ICMP socket that sets Don't Fragment and ignores
// the cached path MTU (IP_PMTUDISC_PROBE), so every size is really tested.
func newEchoSender(address netip.Addr) (echoSender, error) {
	c, e := net.ListenPacket("ip4:icmp", "0.0.0.0")
	if e != nil {
		return nil, errors.New("icmp unavailable")
	}
	conn := c.(*net.IPConn)
	raw, e := conn.SyscallConn()
	if e != nil {
		_ = conn.Close()
		return nil, e
	}
	var option error
	if e = raw.Control(func(fd uintptr) {
		option = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_IP, syscall.IP_MTU_DISCOVER, syscall.IP_PMTUDISC_PROBE)
	}); e != nil || option != nil {
		_ = conn.Close()
		return nil, errors.New("cannot set Don't Fragment")
	}
	return &rawEcho{conn: conn, address: address, id: uint16(rand.Uint32())}, nil
}

func (r *rawEcho) Close() error { return r.conn.Close() }

func (r *rawEcho) Echo(ctx context.Context, size int) (bool, error) {
	r.seq++
	payload := size - 20 - 8
	message := make([]byte, 8+payload)
	message[0] = 8
	message[4], message[5], message[6], message[7] = byte(r.id>>8), byte(r.id), byte(r.seq>>8), byte(r.seq)
	sum := checksum(message)
	message[2], message[3] = byte(sum>>8), byte(sum)
	deadline := time.Now().Add(800 * time.Millisecond)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	_ = r.conn.SetDeadline(deadline)
	if _, e := r.conn.WriteTo(message, &net.IPAddr{IP: r.address.AsSlice()}); e != nil {
		// EMSGSIZE: larger than the local link; that size cannot pass.
		if errors.Is(e, syscall.EMSGSIZE) {
			return false, nil
		}
		return false, errors.New(classify(e))
	}
	buffer := make([]byte, 9100)
	for {
		if ctx.Err() != nil {
			return false, ctx.Err()
		}
		n, from, e := r.conn.ReadFrom(buffer)
		if e != nil {
			var t interface{ Timeout() bool }
			if errors.As(e, &t) && t.Timeout() {
				return false, nil
			}
			return false, errors.New(classify(e))
		}
		source, ok := from.(*net.IPAddr)
		if !ok || n < 8 || buffer[0] != 0 {
			continue
		}
		if got, ok := netip.AddrFromSlice(source.IP); !ok || got.Unmap() != r.address {
			continue
		}
		if uint16(buffer[4])<<8|uint16(buffer[5]) == r.id && uint16(buffer[6])<<8|uint16(buffer[7]) == r.seq {
			return true, nil
		}
	}
}
