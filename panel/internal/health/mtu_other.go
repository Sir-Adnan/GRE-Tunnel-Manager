//go:build !linux

package health

import (
	"errors"
	"net/netip"
)

func newEchoSender(netip.Addr) (echoSender, error) {
	return nil, errors.New("the MTU test needs a Linux server")
}
