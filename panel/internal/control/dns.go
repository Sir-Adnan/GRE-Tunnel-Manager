package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// DNSName is one cached domain destination (Bash resolve.sh).
type DNSName struct {
	Name      string   `json:"name"`
	Family    int      `json:"family"`
	Checked   int64    `json:"checked"`
	Every     int      `json:"every"`
	Mode      string   `json:"mode"`
	Addresses []string `json:"addresses"`
}

// DNSPolicy is the refresh interval (minutes) and multi-address mode of a name.
type DNSPolicy struct {
	Name  string `json:"name"`
	Every int    `json:"every"`
	Mode  string `json:"mode"`
}

func (p DNSPolicy) valid() bool {
	return model.ValidHostname(p.Name) && p.Every >= 1 && p.Every <= 60 && (p.Mode == "all" || p.Mode == "first")
}

// parseDNSView reads `dns-cache`: name and record lines.
func parseDNSView(out string) ([]DNSName, map[string][]model.Target) {
	names := []DNSName{}
	records := map[string][]model.Target{}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		switch {
		case len(f) == 7 && f[0] == "name" && model.ValidHostname(f[1]):
			family, _ := strconv.Atoi(f[2])
			checked, _ := strconv.ParseInt(f[3], 10, 64)
			every, _ := strconv.Atoi(f[4])
			n := DNSName{Name: f[1], Family: family, Checked: checked, Every: every, Mode: f[5], Addresses: []string{}}
			for _, a := range strings.Split(f[6], ",") {
				if ip, e := netip.ParseAddr(a); e == nil {
					n.Addresses = append(n.Addresses, ip.String())
				}
			}
			names = append(names, n)
		case len(f) == 3 && f[0] == "record" && model.IDPattern.MatchString(f[1]):
			targets := []model.Target{}
			if f[2] != "-" {
				for _, item := range strings.Split(f[2], ",") {
					if t, e := model.ParseTarget(item); e == nil && !t.IsHost() {
						targets = append(targets, t)
					}
				}
			}
			records[f[1]] = targets
		}
	}
	return names, records
}

func hasHosts(c model.Connection) bool {
	for _, t := range c.Targets {
		if t.IsHost() {
			return true
		}
	}
	return false
}

// effectiveTargets are the literal destinations rules use: the resolved list
// for a connection with a DNS name, otherwise its own targets.
func effectiveTargets(c model.Connection) []model.Target {
	if hasHosts(c) {
		return c.Resolved
	}
	return c.Targets
}

// fillResolved attaches resolved destinations to connections that name a domain.
func (m *Manager) fillResolved(ctx context.Context, connections []model.Connection) []DNSName {
	need := false
	for _, c := range connections {
		need = need || hasHosts(c)
	}
	if !need {
		return nil
	}
	out, e := invoke(ctx, m.Runner, "dns-cache", "")
	if e != nil {
		return nil
	}
	names, records := parseDNSView(out)
	for i := range connections {
		if hasHosts(connections[i]) {
			connections[i].Resolved = records[connections[i].ID]
			if connections[i].Resolved == nil {
				connections[i].Resolved = []model.Target{}
			}
		}
	}
	return names
}

// --- Server DNS --------------------------------------------------------------

var dnsPresets = model.DNSPresets()

// ServerDNS is the host resolver state from `dns-status`.
type ServerDNS struct {
	Mode     string            `json:"mode"`
	Managed  bool              `json:"managed"`
	Current  []string          `json:"current"`
	Upstream []string          `json:"upstream"`
	Active   []string          `json:"active"`
	Servers  []string          `json:"servers"`
	Original []string          `json:"original"`
	Presets  []model.DNSPreset `json:"presets"`
}

func parseServerDNS(out string) ServerDNS {
	v := ServerDNS{Current: []string{}, Upstream: []string{}, Servers: []string{}, Original: []string{}, Presets: dnsPresets}
	list := func(s string) []string {
		items := []string{}
		for _, w := range strings.Fields(s) {
			if a, e := netip.ParseAddr(w); e == nil {
				items = append(items, a.String())
			}
		}
		return items
	}
	for _, line := range strings.Split(out, "\n") {
		k, value, _ := strings.Cut(line, "\t")
		switch k {
		case "mode":
			switch value {
			case "resolved", "file", "resolvconf", "networkmanager":
				v.Mode = value
			default:
				v.Mode = "unknown"
			}
		case "managed":
			v.Managed = value == "1"
		case "current":
			v.Current = list(value)
		case "upstream":
			v.Upstream = list(value)
		case "active":
			v.Active = list(value)
		case "servers":
			v.Servers = list(value)
		case "original":
			v.Original = list(value)
		}
	}
	return v
}

// DNSInput carries server DNS and domain-destination requests.
type DNSInput struct {
	Servers []string   `json:"servers,omitempty"`
	Name    string     `json:"name,omitempty"`
	Family  int        `json:"family,omitempty"`
	Policy  *DNSPolicy `json:"policy,omitempty"`
}

// publicResolver accepts addresses a server may query: no loopback,
// unspecified, link-local or multicast (private ranges are valid resolvers).
func publicResolver(value string) (netip.Addr, bool) {
	a, e := netip.ParseAddr(value)
	if e != nil || a.Zone() != "" || a.Is4In6() || a.IsLoopback() || a.IsUnspecified() || a.IsLinkLocalUnicast() || a.IsMulticast() {
		return netip.Addr{}, false
	}
	return a, true
}

func (in DNSInput) servers(limit int) ([]string, error) {
	if len(in.Servers) < 1 || len(in.Servers) > limit {
		return nil, fmt.Errorf("choose 1–%d DNS servers", limit)
	}
	out := []string{}
	seen := map[string]bool{}
	for _, s := range in.Servers {
		a, ok := publicResolver(strings.TrimSpace(s))
		if !ok {
			return nil, fmt.Errorf("not a usable DNS server: %q", s)
		}
		if !seen[a.String()] {
			seen[a.String()] = true
			out = append(out, a.String())
		}
	}
	return out, nil
}

// DNSProbe is one resolver test: median latency over a few names.
type DNSProbe struct {
	Server string  `json:"server"`
	OK     int     `json:"ok"`
	Tried  int     `json:"tried"`
	RTT    float64 `json:"rtt_ms"`
	Error  string  `json:"error,omitempty"`
}

var probeNames = []string{"example.com", "cloudflare.com", "github.com"}

// dnsQuery is replaceable in tests; it resolves name through server only.
var dnsQuery = func(ctx context.Context, server, name string) error {
	r := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	}}
	_, e := r.LookupNetIP(ctx, "ip4", name)
	return e
}

// testResolvers queries every server for each probe name with a 2 s timeout,
// eight servers at a time. It sends nothing but DNS queries.
func testResolvers(ctx context.Context, servers []string) []DNSProbe {
	results := make([]DNSProbe, len(servers))
	var wg sync.WaitGroup
	limit := make(chan struct{}, 8)
	for i, s := range servers {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			limit <- struct{}{}
			defer func() { <-limit }()
			p := DNSProbe{Server: s, Tried: len(probeNames)}
			rtts := []float64{}
			for _, name := range probeNames {
				qctx, cancel := context.WithTimeout(ctx, 2*time.Second)
				start := time.Now()
				e := dnsQuery(qctx, s, name)
				cancel()
				if e != nil {
					p.Error = "timeout"
					var de *net.DNSError
					if errors.As(e, &de) && de.IsNotFound {
						p.Error = "refused"
					}
					continue
				}
				p.OK++
				rtts = append(rtts, float64(time.Since(start).Microseconds())/1000)
			}
			if len(rtts) > 0 {
				sort.Float64s(rtts)
				p.RTT = rtts[len(rtts)/2]
				p.Error = ""
			}
			results[i] = p
		}(i, s)
	}
	wg.Wait()
	return results
}

// dnsTestServers is the request's servers or, when empty, every preset.
func dnsTestServers(in DNSInput) ([]string, error) {
	if len(in.Servers) == 0 {
		out := []string{}
		for _, p := range dnsPresets {
			out = append(out, p.Servers...)
		}
		return out, nil
	}
	return in.servers(32)
}
