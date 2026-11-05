// Package model owns portable panel contracts. Engines keep their native scope;
// the capability registry never promises unsupported arbitrary directives.
package model

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Target is one destination: a literal address or a DNS name, with a port or
// (kernel range records) a one-to-one port range ending at PortLast.
type Target struct {
	IP       string `json:"ip"`
	Port     int    `json:"port"`
	PortLast int    `json:"port_last,omitempty"`
	Weight   int    `json:"weight"`
}
type Connection struct {
	ID        string            `json:"id"`
	Name      string            `json:"name"`
	Engine    string            `json:"engine"`
	Protocol  string            `json:"protocol"`
	Bind      string            `json:"bind"`
	Ports     string            `json:"ports"`
	Strategy  string            `json:"strategy"`
	Enabled   bool              `json:"enabled"`
	SNAT      string            `json:"snat"`
	Interface string            `json:"interface"`
	Targets   []Target          `json:"targets"`
	Options   map[string]string `json:"options"`
	Revision  string            `json:"revision"`
	Status    string            `json:"status,omitempty"`
	Routing   *Routing          `json:"routing,omitempty"`
	// PortMode maps several local ports or ranges on create: "" uses each
	// target's port, "same" keeps the local port numbers, "map" uses RemotePorts
	// in the same order and sizes.
	PortMode    string `json:"port_mode,omitempty"`
	RemotePorts string `json:"remote_ports,omitempty"`
	// Resolved lists the addresses a DNS destination currently uses (read only).
	Resolved []Target `json:"resolved,omitempty"`
}
type Capability struct {
	ID         string   `json:"id"`
	Protocols  []string `json:"protocols"`
	Strategies []string `json:"strategies"`
	Options    []Option `json:"options"`
	Scope      string   `json:"scope"`
}
type Option struct {
	Key     string   `json:"key"`
	Min     int      `json:"min,omitempty"`
	Max     int      `json:"max,omitempty"`
	Default string   `json:"default"`
	Choices []string `json:"choices,omitempty"`
	Format  string   `json:"format,omitempty"`
}

var RealmOptions = []Option{
	{Key: "send_mptcp", Default: "false", Choices: []string{"false", "true"}},
	{Key: "accept_mptcp", Default: "false", Choices: []string{"false", "true"}},
	{Key: "ipv6_only", Default: "false", Choices: []string{"false", "true"}},
	{Key: "listen_transport", Default: "plain", Choices: []string{"plain", "ws"}},
	{Key: "remote_transport", Default: "plain", Choices: []string{"plain", "ws"}},
	{Key: "ws_host", Default: "localhost", Format: "http_host"},
	{Key: "ws_path", Default: "/", Format: "http_path"},
	{Key: "tcp_timeout", Min: 1, Max: 300, Default: "5"}, {Key: "udp_timeout", Min: 1, Max: 3600, Default: "30"},
	{Key: "tcp_keepalive", Min: 0, Max: 3600, Default: "15"}, {Key: "tcp_keepalive_probe", Min: 1, Max: 30, Default: "3"},
	{Key: "send_proxy", Default: "false", Choices: []string{"false", "true"}}, {Key: "send_proxy_version", Default: "2", Choices: []string{"1", "2"}},
	{Key: "accept_proxy", Default: "false", Choices: []string{"false", "true"}}, {Key: "accept_proxy_timeout", Min: 1, Max: 300, Default: "5"},
	{Key: "log", Default: "warn", Choices: []string{"off", "error", "warn", "info", "debug", "trace"}},
}
var HAOptions = []Option{
	{Key: "fin", Min: 0, Max: 300, Default: "0"},
	{Key: "tunnel", Min: 0, Max: 604800, Default: "0"},
	{Key: "retries", Min: 0, Max: 5, Default: "3"},
	{Key: "stick", Default: "off", Choices: []string{"off", "source"}},
	{Key: "stick_size", Min: 1024, Max: 1000000, Default: "16384"},
	{Key: "stick_expire", Min: 30, Max: 86400, Default: "1800"},
	{Key: "connect", Min: 1, Max: 300, Default: "5"}, {Key: "idle", Min: 10, Max: 604800, Default: "3600"},
	{Key: "queue", Min: 1, Max: 3600, Default: "30"}, {Key: "maxconn", Min: 0, Max: 1000000, Default: "16384"},
	{Key: "server_maxconn", Min: 0, Max: 1000000, Default: "0"}, {Key: "check_interval", Min: 1, Max: 300, Default: "3"},
	{Key: "check_timeout", Min: 1, Max: 300, Default: "5"}, {Key: "check_fall", Min: 1, Max: 20, Default: "3"},
	{Key: "check_rise", Min: 1, Max: 20, Default: "2"}, {Key: "check_port", Min: 0, Max: 65535, Default: "0"},
	{Key: "slowstart", Min: 0, Max: 3600, Default: "0"}, {Key: "proxy", Default: "off", Choices: []string{"off", "v1", "v2"}},
	{Key: "log", Default: "connections", Choices: []string{"connections", "errors", "off"}},
	{Key: "check_mode", Default: "tcp", Choices: []string{"off", "tcp", "http"}},
	{Key: "check_path", Default: "/health", Format: "http_path"},
	{Key: "check_host", Default: "localhost", Format: "http_host"},
	{Key: "check_status", Min: 200, Max: 599, Default: "200"},
}

func Capabilities() []Capability {
	return []Capability{
		{ID: "nftables", Protocols: []string{"tcp", "udp", "both"}, Strategies: []string{"single", "random", "roundrobin", "source"}, Options: []Option{}, Scope: "Owned DNAT with random, incremental or source-IP hash distribution; no active health checks"},
		{ID: "iptables", Protocols: []string{"tcp", "udp", "both"}, Strategies: []string{"single", "random"}, Options: []Option{}, Scope: "Kernel DNAT; weighted distribution, no active health checks"},
		{ID: "haproxy", Protocols: []string{"tcp"}, Strategies: []string{"single", "roundrobin", "leastconn", "source", "failover"}, Options: HAOptions, Scope: "Managed TCP forwarding with health checks; not an arbitrary HTTP/TLS configuration editor"},
		{ID: "realm", Protocols: []string{"tcp", "udp", "both"}, Strategies: []string{"single", "roundrobin", "source"}, Options: RealmOptions, Scope: "TCP/UDP, weights, timeouts, keepalive, PROXY protocol and logs; native encrypted transports are not exposed"},
	}
}

var safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_. -]{0,39}$`)
var safeInterface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
var IDPattern = regexp.MustCompile(`^F[0-9]{6}$`)
var number = regexp.MustCompile(`^[0-9]{1,7}$`)
var healthPath = regexp.MustCompile(`^/[a-zA-Z0-9/_.~-]{0,127}$`)
var healthHost = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.-]{0,251}[a-zA-Z0-9])?$`)

func contains(items []string, item string) bool {
	for _, value := range items {
		if value == item {
			return true
		}
	}
	return false
}
func (c Connection) Capability() (Capability, error) {
	for _, cap := range Capabilities() {
		if cap.ID == c.Engine {
			return cap, nil
		}
	}
	return Capability{}, errors.New("unsupported engine")
}
func validIP(value string) (netip.Addr, error) {
	a, err := netip.ParseAddr(value)
	if err != nil || a.Zone() != "" || a.Is4In6() {
		return netip.Addr{}, errors.New("enter a literal IPv4 or IPv6 address")
	}
	return a, nil
}
func (c Connection) Rows(id string) ([]string, error) {
	if !IDPattern.MatchString(id) {
		return nil, errors.New("invalid connection ID")
	}
	cap, err := c.Capability()
	if err != nil {
		return nil, err
	}
	if !contains(cap.Protocols, c.Protocol) || !contains(cap.Strategies, c.Strategy) {
		return nil, errors.New("protocol or balancing method is unsupported by this engine")
	}
	// An unspecified kernel bind (0.0.0.0 or ::) matches every local address of
	// that family, so servers with additional IPs forward on each of them.
	kernel := c.Engine == "nftables" || c.Engine == "iptables"
	spans, err := ParsePortSpans(c.Ports, kernel)
	if err != nil {
		return nil, err
	}
	if id != "F000000" && len(spans) != 1 {
		return nil, errors.New("edit one port or range at a time")
	}
	remote, err := c.remoteSpans(spans)
	if err != nil {
		return nil, err
	}
	bind, err := validIP(c.Bind)
	if err != nil {
		return nil, err
	}
	if c.Interface != "any" && !safeInterface.MatchString(c.Interface) {
		return nil, errors.New("invalid interface")
	}
	if c.SNAT != "masquerade" && c.SNAT != "preserve" {
		return nil, errors.New("invalid source-address policy")
	}
	if len(c.Targets) < 1 || len(c.Targets) > 32 || (c.Strategy == "single" && len(c.Targets) != 1) {
		return nil, errors.New("select a compatible number of destinations")
	}
	// Per span, the destinations with their port or one-to-one port range.
	targetsBySpan := make([][]string, len(spans))
	seen := map[string]bool{}
	for _, t := range c.Targets {
		host := ValidHostname(t.IP)
		var ip netip.Addr
		if host {
			if c.Routing != nil {
				return nil, errors.New("routing rules need literal destination addresses")
			}
		} else {
			var e error
			if ip, e = validIP(t.IP); e != nil {
				return nil, errors.New("enter an IPv4 or IPv6 address or a domain name")
			}
			if ip.IsUnspecified() || ip.IsMulticast() {
				return nil, errors.New("invalid destination")
			}
			if kernel && ip.Is4() != bind.Is4() {
				return nil, errors.New("kernel address families must match")
			}
		}
		if t.Weight < 1 || t.Weight > 256 {
			return nil, errors.New("invalid destination weight")
		}
		key := t.IP
		if !host {
			key = ip.String()
		}
		if seen[key+"/"+strconv.Itoa(t.Port)] {
			return nil, errors.New("duplicate destination")
		}
		seen[key+"/"+strconv.Itoa(t.Port)] = true
		for i, span := range spans {
			to := Span{t.Port, t.Port}
			if t.PortLast > t.Port {
				to.Last = t.PortLast
			}
			if remote != nil {
				to = remote[i]
			}
			if to.First < 1 || to.Last > 65535 || to.Last < to.First {
				return nil, errors.New("invalid destination port")
			}
			if to.Len() > 1 && to.Len() != span.Len() {
				return nil, errors.New("a port range maps to one port or to a range of the same size")
			}
			if c.Engine == "iptables" && to.Len() > 1 && to.First != span.First {
				return nil, errors.New("shifted port ranges need nftables; iptables keeps the same ports")
			}
			if !host && ip == bind && to.overlaps(span) {
				return nil, errors.New("destination loops into its own listener")
			}
			out := Target{IP: t.IP, Port: to.First}
			if to.Len() > 1 {
				out.PortLast = to.Last
			}
			targetsBySpan[i] = append(targetsBySpan[i], out.Endpoint()+"@"+strconv.Itoa(t.Weight))
		}
	}
	version := "1"
	options := []string{}
	if len(c.Options) > 0 {
		if c.Engine != "haproxy" && c.Engine != "realm" {
			return nil, errors.New("advanced options are not supported by this adapter")
		}
		for key := range c.Options {
			known := false
			for _, o := range cap.Options {
				if o.Key == key {
					known = true
				}
			}
			if !known {
				return nil, fmt.Errorf("unknown option: %s", key)
			}
		}
		for _, o := range cap.Options {
			value, ok := c.Options[o.Key]
			if !ok {
				continue
			}
			if len(o.Choices) > 0 {
				if !contains(o.Choices, value) {
					return nil, errors.New("invalid option choice")
				}
			} else if o.Format != "" {
				if (o.Format == "http_path" && !healthPath.MatchString(value)) || (o.Format == "http_host" && !healthHost.MatchString(value)) {
					return nil, fmt.Errorf("invalid %s", o.Key)
				}
			} else {
				n, e := strconv.Atoi(value)
				if !number.MatchString(value) || e != nil || n < o.Min || n > o.Max {
					return nil, fmt.Errorf("invalid %s", o.Key)
				}
				value = strconv.Itoa(n)
			}
			options = append(options, o.Key+"="+value)
		}
		version = "2"
		if c.Engine == "realm" {
			version = "3"
		}
	}
	if c.Engine == "haproxy" && c.Options["check_mode"] == "http" {
		port, _ := strconv.Atoi(c.Options["check_port"])
		if port < 1 || port > 65535 {
			return nil, errors.New("HTTP readiness requires a separate check port")
		}
		for _, target := range c.Targets {
			if target.Port == port {
				return nil, errors.New("HTTP readiness port must differ from traffic destination ports")
			}
		}
	}
	if c.Engine == "haproxy" && c.Options["check_mode"] == "off" && c.Strategy == "failover" {
		return nil, errors.New("failover requires TCP or HTTP health checks")
	}
	if c.Engine == "realm" {
		if c.Options["ipv6_only"] == "true" && bind.Is4() {
			return nil, errors.New("IPv6-only requires an IPv6 listener")
		}
		if c.Protocol == "udp" && (c.Options["send_mptcp"] == "true" || c.Options["accept_mptcp"] == "true") {
			return nil, errors.New("MPTCP applies to TCP only")
		}
		if c.Protocol != "tcp" && (c.Options["listen_transport"] == "ws" || c.Options["remote_transport"] == "ws") {
			return nil, errors.New("WebSocket profiles require TCP-only traffic")
		}
	}
	enabled := "0"
	routing := ""
	if c.Routing != nil {
		if c.Engine != "haproxy" {
			return nil, errors.New("routing requires HAProxy")
		}
		routing, err = c.Routing.Encode(len(c.Targets))
		if err != nil {
			return nil, err
		}
		version = "4"
		if len(options) == 0 {
			options = append(options, "connect=5")
		}
	}
	if c.Enabled {
		enabled = "1"
	}
	rows := []string{}
	for i, span := range spans {
		port := span.First
		targets := targetsBySpan[i]
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("%s-%d", c.Engine, port)
		} else if len(spans) > 1 {
			if len(name) > 32 {
				name = name[:32]
			}
			name += fmt.Sprintf("-%d", port)
		}
		if !safeName.MatchString(name) {
			return nil, errors.New("name must be 1–40 ASCII letters, digits, spaces, dots, dashes or underscores")
		}
		row := strings.Join([]string{id, name, c.Engine, c.Protocol, c.Bind, span.String(), c.Strategy, enabled, c.SNAT, c.Interface, strings.Join(targets, ","), version}, "\t")
		if version == "2" || version == "3" || version == "4" {
			row += "\t" + strings.Join(options, ";")
		}
		if version == "4" {
			row += "\t" + routing
		}
		rows = append(rows, row)
	}
	return rows, nil
}

// remoteSpans returns the per-span destination ports of PortMode "same" or
// "map", or nil when each target's own port applies.
func (c Connection) remoteSpans(spans []Span) ([]Span, error) {
	switch c.PortMode {
	case "", "fixed":
		return nil, nil
	case "same":
		return spans, nil
	case "map":
		// Remote ports may repeat: several local ranges can go to one port.
		remote := []Span{}
		for _, word := range strings.Fields(strings.ReplaceAll(c.RemotePorts, ",", " ")) {
			s, e := ParseSpan(word)
			if e != nil {
				return nil, fmt.Errorf("remote ports: %w", e)
			}
			remote = append(remote, s)
		}
		if len(remote) != len(spans) {
			return nil, errors.New("enter as many remote ports or ranges as local ones")
		}
		for i := range spans {
			if remote[i].Len() != spans[i].Len() && remote[i].Len() != 1 {
				return nil, errors.New("each remote range must be the same size as its local range")
			}
		}
		return remote, nil
	}
	return nil, errors.New("invalid port mapping")
}

func Revision(row string) string {
	sum := sha256.Sum256([]byte(row))
	return hex.EncodeToString(sum[:])
}
func ParseState(data string) ([]Connection, map[string]string, error) {
	connections := []Connection{}
	raw := map[string]string{}
	for _, row := range strings.Split(strings.TrimSpace(data), "\n") {
		if row == "" || strings.HasPrefix(row, "#") {
			continue
		}
		f := strings.Split(row, "\t")
		if len(f) != 12 && len(f) != 13 && len(f) != 14 {
			return nil, nil, errors.New("invalid manager state")
		}
		if f[7] != "0" && f[7] != "1" {
			return nil, nil, errors.New("invalid enabled flag")
		}
		if (len(f) == 12 && f[11] != "1") || (len(f) == 13 && ((f[11] != "2" || f[2] != "haproxy") && (f[11] != "3" || f[2] != "realm"))) || (len(f) >= 13 && f[12] == "") || (len(f) == 14 && (f[11] != "4" || f[2] != "haproxy")) {
			return nil, nil, errors.New("unsupported record version")
		}
		c := Connection{ID: f[0], Name: f[1], Engine: f[2], Protocol: f[3], Bind: f[4], Ports: f[5], Strategy: f[6], Enabled: f[7] == "1", SNAT: f[8], Interface: f[9], Targets: []Target{}, Options: map[string]string{}, Revision: Revision(row)}
		for _, target := range strings.Split(f[10], ",") {
			t, e := ParseTarget(target)
			if e != nil {
				return nil, nil, e
			}
			if a, e := netip.ParseAddr(t.IP); e == nil {
				t.IP = a.String()
			}
			c.Targets = append(c.Targets, t)
		}
		if len(f) >= 13 {
			for _, pair := range strings.Split(f[12], ";") {
				k, v, ok := strings.Cut(pair, "=")
				if !ok {
					return nil, nil, errors.New("invalid advanced options")
				}
				c.Options[k] = v
			}
		}
		if len(f) == 14 {
			var e error
			c.Routing, e = parseRouting(f[13])
			if e != nil {
				return nil, nil, e
			}
		}
		if _, e := c.Rows(c.ID); e != nil {
			return nil, nil, e
		}
		if _, exists := raw[c.ID]; exists {
			return nil, nil, errors.New("duplicate connection ID")
		}
		raw[c.ID] = row
		connections = append(connections, c)
	}
	sort.Slice(connections, func(i, j int) bool { return connections[i].ID < connections[j].ID })
	return connections, raw, nil
}
