package control

import (
	"context"
	"errors"
	"net/netip"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// DNSResolve is a destination preview: what a name resolves to now.
type DNSResolve struct {
	Name      string   `json:"name"`
	Family    int      `json:"family"`
	Addresses []string `json:"addresses"`
}

// DNSRefresh is one name's outcome of a refresh run.
type DNSRefresh struct {
	Name      string   `json:"name"`
	Family    int      `json:"family"`
	Status    string   `json:"status"`
	Addresses []string `json:"addresses"`
}

func addressList(text string) []string {
	out := []string{}
	for _, w := range strings.FieldsFunc(text, func(r rune) bool { return r == ',' || r == '\n' || r == ' ' }) {
		if a, e := netip.ParseAddr(w); e == nil {
			out = append(out, a.String())
		}
	}
	return out
}

func parseDNSRefresh(out string) []DNSRefresh {
	items := []DNSRefresh{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		if len(f) != 4 || !model.ValidHostname(f[0]) || !oneOf(f[2], "cached", "same", "changed", "failed") {
			continue
		}
		family, _ := strconv.Atoi(f[1])
		items = append(items, DNSRefresh{Name: f[0], Family: family, Status: f[2], Addresses: addressList(f[3])})
	}
	return items
}

func dnsFamily(f int) (string, error) {
	switch f {
	case 0, 4:
		return "4", nil
	case 6:
		return "6", nil
	}
	return "", errors.New("family must be 4 or 6")
}

// dns serves server DNS (status, test, apply, restore) and domain destinations
// (resolve preview, policy, refresh). Every write is a fixed engine operation.
func (m *Manager) dns(ctx context.Context, r Request) (any, error) {
	in := r.DNS
	switch r.Action {
	case "dns":
		out, e := m.call(ctx, "dns-status", "")
		if e != nil {
			return nil, e
		}
		return parseServerDNS(out), nil
	case "dns-test":
		servers, e := dnsTestServers(in)
		if e != nil {
			return nil, e
		}
		return testResolvers(ctx, servers), nil
	case "dns-resolve":
		if !model.ValidHostname(in.Name) {
			return nil, errors.New("enter a domain name such as backend.example.com")
		}
		family, e := dnsFamily(in.Family)
		if e != nil {
			return nil, e
		}
		out, _ := invoke(ctx, m.Runner, "dns-resolve", "", in.Name, family)
		f, _ := strconv.Atoi(family)
		return DNSResolve{Name: in.Name, Family: f, Addresses: addressList(out)}, nil
	case "dns-apply":
		servers, e := in.servers(4)
		if e != nil {
			return nil, e
		}
		return m.call(ctx, "dns-apply", "", servers...)
	case "dns-restore":
		return m.call(ctx, "dns-restore", "")
	case "dns-policy":
		if in.Policy == nil || !in.Policy.valid() {
			return nil, errors.New("choose a refresh interval of 1–60 minutes and all or first address")
		}
		return m.call(ctx, "dns-policy", "", in.Policy.Name, strconv.Itoa(in.Policy.Every), in.Policy.Mode)
	case "dns-refresh":
		out, e := m.call(ctx, "dns-refresh", "")
		if e != nil {
			return nil, e
		}
		return parseDNSRefresh(out), nil
	}
	return nil, errors.New("unknown DNS action")
}
