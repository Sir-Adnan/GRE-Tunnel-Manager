package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// Firewall: the host firewall report from `firewall-status` and the owned
// settings in firewall.tsv (per-connection access rules, abuse protection and
// tagged UFW openings). Writes go through one fixed engine operation that can
// arm an automatic revert; see src/guard.sh.

const (
	firewallSourcesMax    = 128
	firewallExceptionsMax = 128
	firewallLimitMax      = 100000
)

// FirewallAccess limits who may use one connection.
type FirewallAccess struct {
	ID string `json:"id"`
	// Mode is off, allow (only Sources) or deny (everyone but Sources).
	Mode    string   `json:"mode"`
	Sources []string `json:"sources"`
	// PerIP caps concurrent connections per source; Rate caps new
	// connections per second per source. Zero turns either off.
	PerIP int `json:"per_ip"`
	Rate  int `json:"rate"`
}

// FirewallSettings mirrors firewall.tsv.
type FirewallSettings struct {
	// PrivateRanges drops new uplink traffic to private ranges (abuse reports);
	// SMTP drops new uplink connections to port 25.
	PrivateRanges bool             `json:"private_ranges"`
	SMTP          bool             `json:"smtp"`
	Exceptions    []string         `json:"exceptions"`
	Access        []FirewallAccess `json:"access"`
	// UFW lists connections whose ports are kept open in UFW.
	UFW []string `json:"ufw"`
}

// FirewallInput is a settings change. Revision is the one the editor loaded;
// Seconds > 0 reverts the change unless it is confirmed in time.
type FirewallInput struct {
	Revision string           `json:"revision"`
	Settings FirewallSettings `json:"settings"`
	Seconds  int              `json:"seconds"`
}

type FirewallUFW struct {
	// State is missing, inactive or active; policies are UFW words such as
	// deny, allow, reject or disabled ("" when unknown).
	State    string `json:"state"`
	Incoming string `json:"incoming"`
	Routed   string `json:"routed"`
}

// FirewallBackend is one iptables backend's view of a family.
type FirewallBackend struct {
	Family  int    `json:"family"`
	Tool    string `json:"tool"`
	Kind    string `json:"kind"`
	Input   string `json:"input"`
	Forward string `json:"forward"`
	// Guard: the owned GTM_FWD accept is hooked into FORWARD.
	Guard bool `json:"guard"`
}

// FirewallPort is one listening port of a connection and its UFW state:
// tagged (opened by this manager), open, closed or "" without UFW.
type FirewallPort struct {
	ID       string `json:"id"`
	Protocol string `json:"protocol"`
	Port     string `json:"port"`
	UFW      string `json:"ufw"`
}

type FirewallCounter struct {
	Rule    string `json:"rule"`
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

type FirewallStatus struct {
	Revision string `json:"revision"`
	NFT      bool   `json:"nft"`
	// Applied is set while settings ask for rules: whether the table is loaded.
	Applied        *bool             `json:"applied,omitempty"`
	Pending        *time.Time        `json:"pending,omitempty"`
	UFW            FirewallUFW       `json:"ufw"`
	Firewalld      string            `json:"firewalld,omitempty"`
	Docker         bool              `json:"docker"`
	Backends       []FirewallBackend `json:"backends"`
	Tables         []string          `json:"tables"`
	Uplinks        []string          `json:"uplinks"`
	SSH            []int             `json:"ssh"`
	AutoExceptions []string          `json:"auto_exceptions"`
	Ports          []FirewallPort    `json:"ports"`
	Counters       []FirewallCounter `json:"counters"`
	Settings       FirewallSettings  `json:"settings"`
}

var firewallIface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)

var firewallWord = func(s string) string {
	for _, r := range s {
		if (r < 'a' || r > 'z') && r != '-' && r != '_' {
			return ""
		}
	}
	if len(s) > 16 {
		return ""
	}
	return s
}

func emptyFirewallSettings() FirewallSettings {
	return FirewallSettings{Exceptions: []string{}, Access: []FirewallAccess{}, UFW: []string{}}
}

func parseFirewallStatus(out string) FirewallStatus {
	v := FirewallStatus{Backends: []FirewallBackend{}, Tables: []string{}, Uplinks: []string{}, SSH: []int{}, AutoExceptions: []string{}, Ports: []FirewallPort{}, Counters: []FirewallCounter{}, Settings: emptyFirewallSettings(), UFW: FirewallUFW{State: "missing"}}
	upper := func(s string) string {
		if oneOf(s, "ACCEPT", "DROP", "REJECT") {
			return s
		}
		return ""
	}
	for _, line := range strings.Split(out, "\n") {
		f := strings.Split(line, "\t")
		switch f[0] {
		case "revision":
			if len(f) == 2 && (f[1] == "none" || digestValid(f[1])) {
				v.Revision = f[1]
			}
		case "nft":
			v.NFT = len(f) == 2 && f[1] == "available"
		case "applied":
			applied := len(f) == 2 && f[1] == "1"
			v.Applied = &applied
		case "pending":
			if len(f) == 2 {
				if n, e := strconv.ParseInt(f[1], 10, 64); e == nil && n > 0 {
					t := time.Unix(n, 0).UTC()
					v.Pending = &t
				}
			}
		case "ufw":
			if len(f) == 4 && oneOf(f[1], "missing", "inactive", "active") {
				v.UFW = FirewallUFW{State: f[1], Incoming: firewallWord(f[2]), Routed: firewallWord(f[3])}
			}
		case "firewalld":
			if len(f) == 2 && oneOf(f[1], "active", "inactive") {
				v.Firewalld = f[1]
			}
		case "docker":
			v.Docker = true
		case "backend":
			if len(f) == 7 && oneOf(f[1], "4", "6") && oneOf(f[2], "iptables", "ip6tables", "iptables-legacy", "ip6tables-legacy", "iptables-nft", "ip6tables-nft") && oneOf(f[3], "nf_tables", "legacy") {
				family, _ := strconv.Atoi(f[1])
				v.Backends = append(v.Backends, FirewallBackend{Family: family, Tool: f[2], Kind: f[3], Input: upper(f[4]), Forward: upper(f[5]), Guard: f[6] == "1"})
			}
		case "table":
			if len(f) == 2 && len(f[1]) <= 80 && !strings.ContainsAny(f[1], "\"'<>") {
				v.Tables = append(v.Tables, f[1])
			}
		case "uplink":
			if len(f) == 2 && firewallIface.MatchString(f[1]) {
				v.Uplinks = append(v.Uplinks, f[1])
			}
		case "ssh":
			if len(f) == 2 {
				if n, e := strconv.Atoi(f[1]); e == nil && n > 0 && n < 65536 && !slices.Contains(v.SSH, n) {
					v.SSH = append(v.SSH, n)
				}
			}
		case "auto-except":
			if len(f) == 2 {
				if a, e := netip.ParseAddr(f[1]); e == nil {
					v.AutoExceptions = append(v.AutoExceptions, a.String())
				}
			}
		case "port":
			if len(f) == 5 && model.IDPattern.MatchString(f[1]) && oneOf(f[2], "tcp", "udp") && validUFWPort(f[3]) && oneOf(f[4], "-", "tagged", "open", "closed") {
				state := f[4]
				if state == "-" {
					state = ""
				}
				v.Ports = append(v.Ports, FirewallPort{ID: f[1], Protocol: f[2], Port: strings.ReplaceAll(f[3], ":", "-"), UFW: state})
			}
		case "counter":
			if len(f) == 4 && firewallRule(f[1]) {
				p, e1 := strconv.ParseUint(f[2], 10, 64)
				b, e2 := strconv.ParseUint(f[3], 10, 64)
				if e1 == nil && e2 == nil {
					v.Counters = append(v.Counters, FirewallCounter{Rule: strings.TrimPrefix(f[1], "gtm-"), Packets: p, Bytes: b})
				}
			}
		case "setting":
			readFirewallSetting(&v.Settings, f[1:])
		}
	}
	return v
}

func validUFWPort(s string) bool {
	a, b, ranged := strings.Cut(s, ":")
	x, e := strconv.Atoi(a)
	if e != nil || x < 1 || x > 65535 {
		return false
	}
	if !ranged {
		return true
	}
	y, e := strconv.Atoi(b)
	return e == nil && y > x && y <= 65535
}

// firewallRule accepts the engine's counter comments: gtm-private, gtm-smtp
// and gtm-<ID>-allow|deny|rate|conn.
func firewallRule(s string) bool {
	if s == "gtm-private" || s == "gtm-smtp" {
		return true
	}
	id, kind, ok := strings.Cut(strings.TrimPrefix(s, "gtm-"), "-")
	return ok && strings.HasPrefix(s, "gtm-") && model.IDPattern.MatchString(id) && oneOf(kind, "allow", "deny", "rate", "conn")
}

func readFirewallSetting(s *FirewallSettings, f []string) {
	switch {
	case len(f) == 3 && f[0] == "protect" && f[1] == "private":
		s.PrivateRanges = f[2] == "1"
	case len(f) == 3 && f[0] == "protect" && f[1] == "smtp":
		s.SMTP = f[2] == "1"
	case len(f) == 2 && f[0] == "except":
		if p, e := firewallSource(f[1]); e == nil {
			s.Exceptions = append(s.Exceptions, p)
		}
	case len(f) == 2 && f[0] == "ufw" && model.IDPattern.MatchString(f[1]):
		s.UFW = append(s.UFW, f[1])
	case len(f) == 6 && f[0] == "access" && model.IDPattern.MatchString(f[1]) && oneOf(f[2], "off", "allow", "deny"):
		perIP, _ := strconv.Atoi(f[3])
		rate, _ := strconv.Atoi(f[4])
		a := FirewallAccess{ID: f[1], Mode: f[2], Sources: []string{}, PerIP: perIP, Rate: rate}
		if f[5] != "-" {
			for _, c := range strings.Split(f[5], ",") {
				if p, e := firewallSource(c); e == nil {
					a.Sources = append(a.Sources, p)
				}
			}
		}
		s.Access = append(s.Access, a)
	}
}

// firewallSource canonicalizes an address or network: host bits are cleared
// ("203.0.113.7/24" becomes "203.0.113.0/24") and a full-length prefix is
// written as a plain address.
func firewallSource(value string) (string, error) {
	value = strings.TrimSpace(value)
	bad := fmt.Errorf("%q is not an IP address or network such as 203.0.113.0/24", value)
	if strings.Contains(value, "/") {
		p, e := netip.ParsePrefix(value)
		if e != nil || p.Addr().Zone() != "" || p.Addr().Is4In6() || p.Bits() == 0 {
			return "", bad
		}
		p = p.Masked()
		if p.IsSingleIP() {
			return p.Addr().String(), nil
		}
		return p.String(), nil
	}
	a, e := netip.ParseAddr(value)
	if e != nil || a.Zone() != "" || a.Is4In6() || a.IsUnspecified() {
		return "", bad
	}
	return a.String(), nil
}

func firewallSources(values []string, limit int) ([]string, error) {
	out := []string{}
	for _, v := range values {
		p, e := firewallSource(v)
		if e != nil {
			return nil, e
		}
		if !slices.Contains(out, p) {
			out = append(out, p)
		}
	}
	if len(out) > limit {
		return nil, fmt.Errorf("use at most %d addresses or networks", limit)
	}
	return out, nil
}

// lines validates the settings and renders firewall.tsv lines. Connection
// IDs must be known; an allow list needs a source of the connection's family.
func (s FirewallSettings) lines(connections []model.Connection) ([]string, error) {
	byID := map[string]model.Connection{}
	for _, c := range connections {
		byID[c.ID] = c
	}
	out := []string{fmt.Sprintf("protect\tprivate\t%s", boolDigit(s.PrivateRanges)), fmt.Sprintf("protect\tsmtp\t%s", boolDigit(s.SMTP))}
	exceptions, e := firewallSources(s.Exceptions, firewallExceptionsMax)
	if e != nil {
		return nil, e
	}
	for _, x := range exceptions {
		out = append(out, "except\t"+x)
	}
	seen := map[string]bool{}
	for _, a := range s.Access {
		c, ok := byID[a.ID]
		if !ok || seen[a.ID] {
			return nil, fmt.Errorf("connection %s is unknown or listed twice; reload the page", a.ID)
		}
		seen[a.ID] = true
		if !oneOf(a.Mode, "off", "allow", "deny") || a.PerIP < 0 || a.PerIP > firewallLimitMax || a.Rate < 0 || a.Rate > firewallLimitMax {
			return nil, fmt.Errorf("%s: choose off, allow or deny and limits of 0–%d", c.Name, firewallLimitMax)
		}
		sources, e := firewallSources(a.Sources, firewallSourcesMax)
		if e != nil {
			return nil, fmt.Errorf("%s: %w", c.Name, e)
		}
		if a.Mode == "off" {
			sources = []string{}
		}
		if a.Mode != "off" && len(sources) == 0 {
			return nil, fmt.Errorf("%s: add at least one address or network", c.Name)
		}
		if a.Mode == "allow" {
			v6 := strings.Contains(c.Bind, ":")
			if !slices.ContainsFunc(sources, func(p string) bool { return strings.Contains(p, ":") == v6 }) {
				return nil, fmt.Errorf("%s: the allow list needs an address of the connection's family (IPv%s)", c.Name, map[bool]string{false: "4", true: "6"}[v6])
			}
		}
		if a.Mode == "off" && a.PerIP == 0 && a.Rate == 0 {
			continue
		}
		list := "-"
		if len(sources) > 0 {
			list = strings.Join(sources, ",")
		}
		out = append(out, fmt.Sprintf("access\t%s\t%s\t%d\t%d\t%s", a.ID, a.Mode, a.PerIP, a.Rate, list))
	}
	seenUFW := map[string]bool{}
	for _, id := range s.UFW {
		if _, ok := byID[id]; !ok || seenUFW[id] {
			return nil, fmt.Errorf("connection %s is unknown or listed twice; reload the page", id)
		}
		seenUFW[id] = true
		out = append(out, "ufw\t"+id)
	}
	return out, nil
}

func boolDigit(b bool) string {
	if b {
		return "1"
	}
	return "0"
}

func (in FirewallInput) validate(connections []model.Connection) (string, error) {
	if in.Revision != "none" && !digestValid(in.Revision) {
		return "", errors.New("reload the firewall page before saving")
	}
	if in.Seconds != 0 && (in.Seconds < 30 || in.Seconds > 900) {
		return "", errors.New("the confirmation window must be 30–900 seconds")
	}
	lines, e := in.Settings.lines(connections)
	if e != nil {
		return "", e
	}
	return in.Revision + "\n" + strings.Join(lines, "\n") + "\n", nil
}

// firewall serves the report and the three fixed write operations.
func (m *Manager) firewall(ctx context.Context, r Request) (any, error) {
	switch r.Action {
	case "firewall":
		out, e := m.call(ctx, "firewall-status", "")
		if e != nil {
			return nil, e
		}
		return parseFirewallStatus(out), nil
	case "firewall-apply":
		connections, _, e := m.state(ctx)
		if e != nil {
			return nil, e
		}
		input, e := r.Firewall.validate(connections)
		if e != nil {
			return nil, e
		}
		return m.call(ctx, "firewall-apply", input, strconv.Itoa(r.Firewall.Seconds))
	case "firewall-confirm", "firewall-revert":
		return m.call(ctx, r.Action, "")
	case "firewall-repair":
		// Reapplies owned kernel rules: the FORWARD accept goes into every
		// backend that drops, and guard rules and UFW openings are reloaded.
		return m.call(ctx, "kernel-refresh", "")
	}
	return nil, errors.New("unknown firewall action")
}
