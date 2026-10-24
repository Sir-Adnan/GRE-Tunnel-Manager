package control

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

type Selection struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
}
type GRE struct {
	ID     int    `json:"id"`
	Role   string `json:"role"`
	Remote string `json:"remote"`
	Bind   string `json:"bind"`
	MTU    int    `json:"mtu"`
}
type Reverse struct {
	Engine      string `json:"engine"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Host        string `json:"host"`
	Control     int    `json:"control"`
	Public      int    `json:"public"`
	LocalIP     string `json:"local_ip"`
	LocalPort   int    `json:"local_port"`
	Protocol    string `json:"protocol"`
	Transport   string `json:"transport"`
	Mux         bool   `json:"mux"`
	Token       string `json:"token"`
	Group       string `json:"group"`
	Key         string `json:"key"`
	Certificate string `json:"certificate"`
	Internal    int    `json:"internal"`
}
type Resource struct {
	ID          string `json:"id"`
	Engine      string `json:"engine"`
	Name        string `json:"name"`
	Role        string `json:"role"`
	Status      string `json:"status"`
	Interface   string `json:"interface,omitempty"`
	Description string `json:"description"`
	Configured  bool   `json:"configured"`
	Bind        string `json:"bind,omitempty"`
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	Revision    string `json:"revision,omitempty"`
}
type Component struct {
	ID            string `json:"id"`
	Installed     bool   `json:"installed"`
	Version       string `json:"version,omitempty"`
	PeerVersion   string `json:"peer_version,omitempty"`
	Compatibility string `json:"compatibility,omitempty"`
}
type Host struct {
	Hostname        string   `json:"hostname"`
	OS              string   `json:"os"`
	Addresses       []string `json:"addresses"`
	Uptime          string   `json:"uptime"`
	MemoryTotal     uint64   `json:"memory_total"`
	MemoryAvailable uint64   `json:"memory_available"`
	Load            string   `json:"load"`
	PublicIP        string   `json:"public_ip,omitempty"`
}
type Inventory struct {
	Presets        []model.Preset        `json:"presets,omitempty"`
	Connections    []model.Connection    `json:"connections"`
	Resources      []Resource            `json:"resources"`
	Components     []Component           `json:"components"`
	Capabilities   []model.Capability    `json:"capabilities"`
	EngineProfiles []model.EngineProfile `json:"engine_profiles,omitempty"`
	Host           Host                  `json:"host"`
	Version        string                `json:"version"`
	Demo           bool                  `json:"demo"`
}
type Request struct {
	Backup          BackupInput      `json:"backup,omitzero"`
	Configuration   ConfigInput      `json:"configuration,omitzero"`
	NodeTask        *NodeTask        `json:"node_task,omitempty"`
	Action          string           `json:"action"`
	Connection      model.Connection `json:"connection"`
	Selected        []Selection      `json:"selected"`
	GRE             GRE              `json:"gre"`
	Reverse         Reverse          `json:"reverse"`
	Service         string           `json:"service"`
	Verb            string           `json:"verb"`
	Components      []string         `json:"components"`
	Metrics         MetricsSettings  `json:"metrics"`
	MetricsRevision *uint64          `json:"metrics_revision,omitempty"`
	Traffic         TrafficChange    `json:"traffic"`
	ResourceName    ResourceName     `json:"resource_name"`
}
type Manager struct {
	probes    componentProbe
	Runner    Runner
	ConfigDir string
	UnitDir   string
	Metrics   *Metrics
}

func NewManager() *Manager {
	return &Manager{Runner: Executor{}, ConfigDir: "/etc/gre-manager", UnitDir: "/etc/systemd/system"}
}

var reverseID = regexp.MustCompile(`^gtm-(frp|rathole)-(entrance|destination)-[a-zA-Z0-9_-]{1,32}$`)
var greID = regexp.MustCompile(`^gre-tun-([0-9]{1,3})$`)

func ServiceOK(id string) bool {
	if reverseID.MatchString(id) {
		return true
	}
	if model.IDPattern.MatchString(strings.TrimPrefix(id, "gtm-")) && strings.HasPrefix(id, "gtm-") {
		return true
	}
	m := greID.FindStringSubmatch(id)
	if m != nil {
		n, _ := strconv.Atoi(m[1])
		return n >= 1 && n <= 250
	}
	return false
}
func (m *Manager) state(ctx context.Context) ([]model.Connection, map[string]string, error) {
	out, e := invoke(ctx, m.Runner, "state", "")
	if e != nil {
		return nil, nil, fmt.Errorf("%w: %s", e, out)
	}
	return model.ParseState(out)
}
func (m *Manager) Inventory(ctx context.Context) (Inventory, error) {
	connections, _, e := m.state(ctx)
	if e != nil {
		return Inventory{}, e
	}
	resources := []Resource{}
	names, e := m.resourceNames()
	if e != nil {
		return Inventory{}, e
	}
	units := []string{}
	for _, c := range connections {
		if c.Engine == "haproxy" || c.Engine == "realm" {
			units = append(units, "gtm-"+c.ID)
		}
	}
	files, e := os.ReadDir(m.UnitDir)
	if e != nil && !os.IsNotExist(e) {
		return Inventory{}, e
	}
	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(file.Name(), ".service") {
			continue
		}
		id := strings.TrimSuffix(file.Name(), ".service")
		if !reverseID.MatchString(id) && !greID.MatchString(id) {
			continue
		}
		if !ServiceOK(id) {
			continue
		}
		data, e := os.ReadFile(filepath.Join(m.UnitDir, file.Name()))
		if e != nil {
			return Inventory{}, e
		}
		text := string(data)
		resource := Resource{ID: id, Name: id, Status: "unknown"}
		if greID.MatchString(id) {
			resource.Engine = "gre"
			resource.Role = "kharej"
			tid := strings.TrimPrefix(id, "gre-tun-")
			resource.Interface = "gre" + tid
			if strings.Contains(text, "gre-out-"+tid) {
				resource.Role = "iran"
				resource.Interface = "gre-out-" + tid
			}
			resource.Configured = true
		} else {
			parts := strings.SplitN(strings.TrimPrefix(id, "gtm-"), "-", 3)
			resource.Engine = parts[0]
			resource.Role = parts[1]
			resource.Name = parts[2]
			resource.Configured = true
			readReverseListener(m.ConfigDir, &resource)
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(line, "Description=") {
				resource.Description = strings.TrimPrefix(line, "Description=")
			}
		}
		applyResourceName(&resource, data, names[id])
		resources = append(resources, resource)
		units = append(units, id)
	}
	states := map[string]string{}
	if len(units) > 0 {
		args := append([]string{"show", "--no-pager", "--property=Id,ActiveState"}, units...)
		out, _ := m.Runner.Run(ctx, "systemctl", args, "")
		for _, block := range strings.Split(out, "\n\n") {
			id, state := "", ""
			for _, line := range strings.Split(block, "\n") {
				if strings.HasPrefix(line, "Id=") {
					id = strings.TrimSuffix(strings.TrimPrefix(line, "Id="), ".service")
				}
				if strings.HasPrefix(line, "ActiveState=") {
					state = strings.TrimPrefix(line, "ActiveState=")
				}
			}
			if id != "" && state != "" {
				states[id] = state
			}
		}
	}
	for i := range connections {
		c := &connections[i]
		c.Status = "disabled"
		if c.Enabled {
			if c.Engine == "haproxy" || c.Engine == "realm" {
				c.Status = states["gtm-"+c.ID]
				if c.Status == "" {
					c.Status = "unknown"
				}
			} else {
				c.Status = "configured"
			}
		}
	}
	for i := range resources {
		if value := states[resources[i].ID]; value != "" {
			resources[i].Status = value
		}
	}
	return Inventory{Presets: model.Presets(), Connections: connections, Resources: resources, Components: m.components(ctx), Capabilities: model.Capabilities(), EngineProfiles: model.EngineProfiles(), Host: hostInfo(), Version: "1.3.3"}, nil
}
func (m *Manager) Execute(ctx context.Context, r Request) (any, error) {
	switch r.Action {
	case "backup-export", "backup-review", "backup-restore":
		return m.backup(ctx, r.Action, r.Backup)
	case "configuration":
		return m.Configuration(ctx, r.Configuration)
	case "configuration-review", "configuration-apply":
		next, view, e := m.ReviewConfiguration(ctx, r.Configuration)
		if e != nil {
			return nil, e
		}
		if r.Action == "configuration-review" {
			return view, nil
		}
		return m.Execute(ctx, Request{Action: "update", Connection: next, Selected: []Selection{{ID: r.Configuration.ID, Revision: r.Configuration.Revision}}})
	case "inventory":
		return m.Inventory(ctx)
	case "capabilities":
		return model.Capabilities(), nil
	case "resource-rename":
		v := r.ResourceName
		parts := strings.Split(v.Revision, ":")
		if len(parts) != 2 || !digestValid(parts[0]) || (parts[1] != "-" && !digestValid(parts[1])) {
			return nil, errors.New("invalid display-name revision; refresh inventory")
		}
		if !ServiceOK(v.ID) || (!greID.MatchString(v.ID) && !reverseID.MatchString(v.ID)) || (v.Name != "" && !resourceNameValid(v.Name)) {
			return nil, errors.New("name must be up to 40 ASCII letters, digits, spaces, dots, dashes or underscores")
		}
		name := v.Name
		if name == "" {
			name = "-"
		}
		return m.call(ctx, "resource-rename", name+"\n", v.ID, v.Revision)
	case "create":
		r.Connection = r.Connection.WithCreationDefaults()
		rows, e := r.Connection.Rows("F000000")
		if e != nil {
			return nil, e
		}
		return m.call(ctx, "create", strings.Join(rows, "\n")+"\n")
	case "update", "enable", "disable", "delete":
		_, raw, e := m.state(ctx)
		if e != nil {
			return nil, e
		}
		if len(r.Selected) < 1 || len(r.Selected) > 128 {
			return nil, errors.New("select 1–128 connections")
		}
		rows := []string{}
		seen := map[string]bool{}
		for _, selection := range r.Selected {
			row, ok := raw[selection.ID]
			if !ok || selection.Revision != model.Revision(row) || seen[selection.ID] {
				return nil, errors.New("selection changed; refresh the list")
			}
			seen[selection.ID] = true
			rows = append(rows, row)
		}
		if r.Action == "update" {
			if len(rows) != 1 {
				return nil, errors.New("edit one connection")
			}
			next, e := r.Connection.Rows(r.Selected[0].ID)
			if e != nil {
				return nil, e
			}
			rows = append(rows, next[0])
		}
		return m.call(ctx, r.Action, strings.Join(rows, "\n")+"\n")
	case "plan", "doctor":
		return m.call(ctx, r.Action, "")
	case "install":
		if len(r.Components) == 0 || len(r.Components) > 6 {
			return nil, errors.New("select components")
		}
		for _, component := range r.Components {
			if !oneOf(component, "iptables", "nftables", "haproxy", "realm", "frp", "rathole") {
				return nil, errors.New("unknown component")
			}
		}
		return m.call(ctx, "install", "", r.Components...)
	case "gre-create":
		g := r.GRE
		if g.ID < 1 || g.ID > 250 || !oneOf(g.Role, "kharej", "iran") || g.MTU < 1280 || g.MTU > 1472 {
			return nil, errors.New("invalid GRE settings")
		}
		a, e := netip.ParseAddr(g.Remote)
		if e != nil || a.Zone() != "" || a.IsUnspecified() || a.IsMulticast() {
			return nil, errors.New("invalid peer IP")
		}
		b, e := netip.ParseAddr(g.Bind)
		if e != nil || b.Zone() != "" || b.IsUnspecified() || a.Is4() != b.Is4() || (!a.Is4() && g.MTU > 1452) {
			return nil, errors.New("invalid local IP or MTU")
		}
		return m.call(ctx, "gre-create", "", strconv.Itoa(g.ID), g.Role, g.Remote, g.Bind, strconv.Itoa(g.MTU))
	case "gre-delete":
		if !greID.MatchString(r.Service) || !ServiceOK(r.Service) {
			return nil, errors.New("invalid GRE ID")
		}
		return m.call(ctx, "gre-delete", "", strings.TrimPrefix(r.Service, "gre-tun-"))
	case "reverse-create":
		input, e := r.Reverse.Input()
		if e != nil {
			return nil, e
		}
		return m.call(ctx, "reverse-create", input)
	case "reverse-delete":
		if !reverseID.MatchString(r.Service) {
			return nil, errors.New("invalid reverse instance")
		}
		return m.call(ctx, "reverse-delete", "", r.Service)
	case "service", "logs":
		if !ServiceOK(r.Service) {
			return nil, errors.New("unmanaged service")
		}
		if _, e := os.Stat(filepath.Join(m.UnitDir, r.Service+".service")); e != nil {
			return nil, e
		}
		if r.Action == "logs" {
			return m.Runner.Run(ctx, "journalctl", []string{"-u", r.Service, "-n", "100", "--no-pager", "--output=short-iso"}, "")
		}
		if r.Verb == "enable" && (greID.MatchString(r.Service) || reverseID.MatchString(r.Service)) {
			return m.Runner.Run(ctx, "systemctl", []string{"enable", "--now", r.Service}, "")
		}
		if !oneOf(r.Verb, "start", "stop", "restart") {
			return nil, errors.New("invalid service action")
		}
		return m.Runner.Run(ctx, "systemctl", []string{r.Verb, r.Service}, "")
	case "metrics":
		if m.Metrics == nil {
			return nil, errors.New("metrics unavailable")
		}
		return m.Metrics.Summary(), nil
	case "metrics-history":
		if m.Metrics == nil {
			return nil, errors.New("metrics unavailable")
		}
		return m.Metrics.Archive(r.Traffic.ID)
	case "metrics-configure":
		if m.Metrics == nil {
			return nil, errors.New("metrics unavailable")
		}
		inventory, e := m.Inventory(ctx)
		if e != nil {
			return nil, e
		}
		if r.MetricsRevision != nil {
			return trafficReceipt(m.Metrics.Configure(ctx, r.Metrics, inventory, *r.MetricsRevision))
		}
		return trafficReceipt(m.Metrics.Configure(ctx, r.Metrics, inventory))
	case "metrics-reset", "metrics-policy", "metrics-forget":
		if m.Metrics == nil {
			return nil, errors.New("metrics unavailable")
		}
		inventory, e := m.Inventory(ctx)
		if e != nil {
			return nil, e
		}
		return trafficReceipt(m.Metrics.Change(ctx, r.Action, r.Traffic, inventory))
	default:
		return nil, errors.New("unsupported operation")
	}
}
func (m *Manager) call(ctx context.Context, action, input string, args ...string) (string, error) {
	out, e := invoke(ctx, m.Runner, action, input, args...)
	if e != nil {
		return out, fmt.Errorf("%w: %s", e, out)
	}
	return out, nil
}
func oneOf(value string, values ...string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}

var instanceName = regexp.MustCompile(`^[a-zA-Z0-9_-]{1,32}$`)
var sharedToken = regexp.MustCompile(`^[a-zA-Z0-9_-]{24,128}$`)
var safePath = regexp.MustCompile(`^/[a-zA-Z0-9_./-]+$`)
var noiseKey = regexp.MustCompile(`^[A-Za-z0-9+/]{43}=$`)

func (r Reverse) Input() (string, error) {
	if !oneOf(r.Engine, "frp", "rathole") || !instanceName.MatchString(r.Name) || !oneOf(r.Role, "entrance", "destination") || !oneOf(r.Protocol, "tcp", "udp", "both") || !sharedToken.MatchString(r.Token) {
		return "", errors.New("invalid reverse name, role, protocol or shared token")
	}
	for _, value := range []string{r.Host, r.LocalIP} {
		ip, e := netip.ParseAddr(value)
		if e != nil || ip.Zone() != "" {
			return "", errors.New("enter literal IP addresses")
		}
	}
	for _, port := range []int{r.Control, r.Public, r.LocalPort} {
		if port < 1 || port > 65535 {
			return "", errors.New("invalid reverse port")
		}
	}
	if r.Control == r.Public {
		return "", errors.New("control and public ports must differ")
	}
	if r.Engine == "frp" {
		if !oneOf(r.Transport, "tcp", "websocket", "wss", "quic") || r.Protocol == "both" || !instanceName.MatchString(r.Group) {
			return "", errors.New("invalid FRP transport, protocol or group")
		}
		if r.Transport == "wss" && (!safePath.MatchString(r.Certificate) || r.Internal < 1 || r.Internal > 65535) {
			return "", errors.New("WSS needs a local certificate/CA path and internal port")
		}
	}
	if r.Engine == "rathole" && r.Role == "destination" && !noiseKey.MatchString(r.Key) {
		return "", errors.New("enter the entrance Noise public key")
	}
	fields := []string{r.Engine, r.Name, r.Role, r.Host, strconv.Itoa(r.Control), strconv.Itoa(r.Public), r.LocalIP, strconv.Itoa(r.LocalPort), r.Protocol, r.Transport, strconv.FormatBool(r.Mux), r.Token, r.Group, r.Key, r.Certificate, strconv.Itoa(r.Internal)}
	for i, value := range fields {
		if value == "" {
			fields[i] = "-"
		}
		if strings.ContainsAny(value, "\t\n\r") {
			return "", errors.New("invalid field")
		}
	}
	return strings.Join(fields, "\t") + "\n", nil
}
func hostInfo() Host {
	host, _ := os.Hostname()
	h := Host{Hostname: host, OS: "Linux", Addresses: []string{}}
	if c, e := config.Load(config.DefaultPath); e == nil {
		h.PublicIP = c.PublicIP
	}
	if data, e := os.ReadFile("/etc/os-release"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "PRETTY_NAME=") {
				h.OS = strings.Trim(strings.TrimPrefix(line, "PRETTY_NAME="), "\"")
			}
		}
	}
	if addresses, e := net.InterfaceAddrs(); e == nil {
		for _, address := range addresses {
			ip, e := netip.ParsePrefix(address.String())
			if e == nil && !ip.Addr().IsLoopback() && !ip.Addr().IsLinkLocalUnicast() {
				h.Addresses = append(h.Addresses, ip.Addr().String())
			}
		}
	}
	if data, e := os.ReadFile("/proc/uptime"); e == nil {
		v := strings.Fields(string(data))
		if len(v) > 0 {
			seconds, _ := strconv.ParseFloat(v[0], 64)
			h.Uptime = (time.Duration(seconds) * time.Second).Round(time.Minute).String()
		}
	}
	if data, e := os.ReadFile("/proc/meminfo"); e == nil {
		for _, line := range strings.Split(string(data), "\n") {
			f := strings.Fields(line)
			if len(f) > 1 {
				n, _ := strconv.ParseUint(f[1], 10, 64)
				if f[0] == "MemTotal:" {
					h.MemoryTotal = n * 1024
				}
				if f[0] == "MemAvailable:" {
					h.MemoryAvailable = n * 1024
				}
			}
		}
	}
	if data, e := os.ReadFile("/proc/loadavg"); e == nil {
		f := strings.Fields(string(data))
		if len(f) > 2 {
			h.Load = strings.Join(f[:3], " ")
		}
	}
	return h
}
