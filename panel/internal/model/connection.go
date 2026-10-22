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

type Target struct {
	IP     string `json:"ip"`
	Port   int    `json:"port"`
	Weight int    `json:"weight"`
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
}

var RealmOptions = []Option{
	{Key: "tcp_timeout", Min: 1, Max: 300, Default: "5"}, {Key: "udp_timeout", Min: 1, Max: 3600, Default: "30"},
	{Key: "tcp_keepalive", Min: 0, Max: 3600, Default: "15"}, {Key: "tcp_keepalive_probe", Min: 1, Max: 30, Default: "3"},
	{Key: "send_proxy", Default: "false", Choices: []string{"false", "true"}}, {Key: "send_proxy_version", Default: "2", Choices: []string{"1", "2"}},
	{Key: "accept_proxy", Default: "false", Choices: []string{"false", "true"}}, {Key: "accept_proxy_timeout", Min: 1, Max: 300, Default: "5"},
	{Key: "log", Default: "warn", Choices: []string{"off", "error", "warn", "info", "debug", "trace"}},
}
var HAOptions = []Option{
	{Key: "connect", Min: 1, Max: 300, Default: "5"}, {Key: "idle", Min: 10, Max: 604800, Default: "3600"},
	{Key: "queue", Min: 1, Max: 3600, Default: "30"}, {Key: "maxconn", Min: 1, Max: 100000, Default: "16384"},
	{Key: "server_maxconn", Min: 0, Max: 100000, Default: "0"}, {Key: "check_interval", Min: 1, Max: 300, Default: "3"},
	{Key: "check_timeout", Min: 1, Max: 300, Default: "5"}, {Key: "check_fall", Min: 1, Max: 20, Default: "3"},
	{Key: "check_rise", Min: 1, Max: 20, Default: "2"}, {Key: "check_port", Min: 0, Max: 65535, Default: "0"},
	{Key: "slowstart", Min: 0, Max: 3600, Default: "0"}, {Key: "proxy", Default: "off", Choices: []string{"off", "v1", "v2"}},
	{Key: "log", Default: "connections", Choices: []string{"connections", "errors", "off"}},
}

func Capabilities() []Capability {
	return []Capability{
		{ID: "nftables", Protocols: []string{"tcp", "udp", "both"}, Strategies: []string{"single", "random"}, Options: []Option{}, Scope: "Kernel DNAT; weighted distribution, no active health checks"},
		{ID: "iptables", Protocols: []string{"tcp", "udp", "both"}, Strategies: []string{"single", "random"}, Options: []Option{}, Scope: "Kernel DNAT; weighted distribution, no active health checks"},
		{ID: "haproxy", Protocols: []string{"tcp"}, Strategies: []string{"single", "roundrobin", "leastconn", "source", "failover"}, Options: HAOptions, Scope: "Managed TCP forwarding with health checks; not an arbitrary HTTP/TLS configuration editor"},
		{ID: "realm", Protocols: []string{"tcp", "udp", "both"}, Strategies: []string{"single", "roundrobin", "source"}, Options: RealmOptions, Scope: "TCP/UDP, weights, timeouts, keepalive, PROXY protocol and logs; native encrypted transports are not exposed"},
	}
}

var safeName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_. -]{0,39}$`)
var safeInterface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
var IDPattern = regexp.MustCompile(`^F[0-9]{6}$`)
var number = regexp.MustCompile(`^[0-9]{1,6}$`)

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
func ParsePorts(value string) ([]int, error) {
	if len(value) > 1024 {
		return nil, errors.New("too many ports")
	}
	words := strings.Fields(strings.ReplaceAll(value, ",", " "))
	if len(words) == 0 {
		return nil, errors.New("enter a local port")
	}
	seen := map[int]bool{}
	ports := []int{}
	for _, word := range words {
		limits := strings.Split(word, "-")
		if len(limits) > 2 {
			return nil, errors.New("invalid port range")
		}
		first, err := strconv.Atoi(limits[0])
		if err != nil || first < 1 || first > 65535 {
			return nil, errors.New("invalid port")
		}
		last := first
		if len(limits) == 2 {
			last, err = strconv.Atoi(limits[1])
			if err != nil || last < first || last > 65535 || last-first >= 32 {
				return nil, errors.New("range must contain at most 32 ports")
			}
		}
		for port := first; port <= last; port++ {
			if !seen[port] {
				seen[port] = true
				ports = append(ports, port)
			}
			if len(ports) > 32 {
				return nil, errors.New("at most 32 ports per operation")
			}
		}
	}
	return ports, nil
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
	ports, err := ParsePorts(c.Ports)
	if err != nil {
		return nil, err
	}
	if id != "F000000" && len(ports) != 1 {
		return nil, errors.New("edit one port at a time")
	}
	bind, err := validIP(c.Bind)
	if err != nil {
		return nil, err
	}
	kernel := c.Engine == "nftables" || c.Engine == "iptables"
	if kernel && bind.IsUnspecified() {
		return nil, errors.New("kernel forwarding requires an assigned local IP")
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
	targets := []string{}
	seen := map[string]bool{}
	for _, t := range c.Targets {
		ip, e := validIP(t.IP)
		if e != nil {
			return nil, e
		}
		if t.Port < 1 || t.Port > 65535 || t.Weight < 1 || t.Weight > 256 || ip.IsUnspecified() || ip.IsMulticast() {
			return nil, errors.New("invalid destination")
		}
		if kernel && ip.Is4() != bind.Is4() {
			return nil, errors.New("kernel address families must match")
		}
		endpoint := netip.AddrPortFrom(ip, uint16(t.Port)).String()
		if seen[endpoint] {
			return nil, errors.New("duplicate destination")
		}
		seen[endpoint] = true
		for _, port := range ports {
			if ip == bind && t.Port == port {
				return nil, errors.New("destination loops into its own listener")
			}
		}
		targets = append(targets, endpoint+"@"+strconv.Itoa(t.Weight))
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
	enabled := "0"
	if c.Enabled {
		enabled = "1"
	}
	rows := []string{}
	for _, port := range ports {
		name := c.Name
		if name == "" {
			name = fmt.Sprintf("%s-%d", c.Engine, port)
		} else if len(ports) > 1 {
			if len(name) > 32 {
				name = name[:32]
			}
			name += fmt.Sprintf("-%d", port)
		}
		if !safeName.MatchString(name) {
			return nil, errors.New("name must be 1–40 ASCII letters, digits, spaces, dots, dashes or underscores")
		}
		row := strings.Join([]string{id, name, c.Engine, c.Protocol, c.Bind, strconv.Itoa(port), c.Strategy, enabled, c.SNAT, c.Interface, strings.Join(targets, ","), version}, "\t")
		if version == "2" {
			row += "\t" + strings.Join(options, ";")
		}
		rows = append(rows, row)
	}
	return rows, nil
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
		if len(f) != 12 && len(f) != 13 {
			return nil, nil, errors.New("invalid manager state")
		}
		if f[7] != "0" && f[7] != "1" {
			return nil, nil, errors.New("invalid enabled flag")
		}
		if (len(f) == 12 && f[11] != "1") || (len(f) == 13 && ((f[11] != "2" || f[2] != "haproxy") && (f[11] != "3" || f[2] != "realm"))) || (len(f) == 13 && f[12] == "") {
			return nil, nil, errors.New("unsupported record version")
		}
		c := Connection{ID: f[0], Name: f[1], Engine: f[2], Protocol: f[3], Bind: f[4], Ports: f[5], Strategy: f[6], Enabled: f[7] == "1", SNAT: f[8], Interface: f[9], Targets: []Target{}, Options: map[string]string{}, Revision: Revision(row)}
		for _, target := range strings.Split(f[10], ",") {
			parts := strings.Split(target, "@")
			ep, e := netip.ParseAddrPort(parts[0])
			if e != nil {
				return nil, nil, e
			}
			weight := 1
			if len(parts) == 2 {
				weight, e = strconv.Atoi(parts[1])
				if e != nil {
					return nil, nil, e
				}
			}
			c.Targets = append(c.Targets, Target{IP: ep.Addr().String(), Port: int(ep.Port()), Weight: weight})
		}
		if len(f) == 13 {
			for _, pair := range strings.Split(f[12], ";") {
				k, v, ok := strings.Cut(pair, "=")
				if !ok {
					return nil, nil, errors.New("invalid advanced options")
				}
				c.Options[k] = v
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
