package control

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

type BackupInput struct {
	Password       string            `json:"password"`
	Archive        string            `json:"archive,omitempty"`
	IncludeTraffic bool              `json:"include_traffic"`
	Addresses      map[string]string `json:"addresses,omitempty"`
	Interfaces     map[string]string `json:"interfaces,omitempty"`
	Revision       string            `json:"revision,omitempty"`
}
type BackupResource struct {
	Name    string   `json:"name,omitempty"`
	GRE     *GRE     `json:"gre,omitempty"`
	Reverse *Reverse `json:"reverse,omitempty"`
}
type recoveryDocument struct {
	Version        int                `json:"version"`
	Created        time.Time          `json:"created"`
	ManagerVersion string             `json:"manager_version"`
	Host           string             `json:"host"`
	Counter        int                `json:"counter"`
	Connections    []model.Connection `json:"connections"`
	Resources      []BackupResource   `json:"resources"`
	Traffic        *MetricsView       `json:"traffic,omitempty"`
}
type BackupItem struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Engine  string `json:"engine"`
	Summary string `json:"summary"`
}
type BackupReview struct {
	Created      time.Time    `json:"created"`
	Host         string       `json:"host"`
	Version      string       `json:"version"`
	Revision     string       `json:"revision"`
	Items        []BackupItem `json:"items"`
	Addresses    []string     `json:"addresses"`
	Interfaces   []string     `json:"interfaces"`
	Certificates []string     `json:"certificates"`
	Traffic      bool         `json:"traffic"`
	Blockers     []string     `json:"blockers"`
}
type BackupDownload struct {
	Filename string `json:"filename"`
	Archive  string `json:"archive"`
}

func (m *Manager) recoverySnapshot(ctx context.Context, traffic bool) (recoveryDocument, error) {
	d := recoveryDocument{Version: 1, Created: time.Now().UTC(), Connections: []model.Connection{}, Resources: []BackupResource{}}
	i, e := m.Inventory(ctx)
	if e != nil {
		return d, e
	}
	d.Host, d.ManagerVersion = i.Host.Hostname, i.Version
	if raw, e := boundedConfig(m.ConfigDir, "id-counter"); e == nil {
		n, e := strconv.Atoi(strings.TrimSpace(raw))
		if e != nil || n < 0 || n > 999999 {
			return d, errors.New("invalid connection counter")
		}
		d.Counter = n
	} else if !os.IsNotExist(e) {
		return d, e
	}
	d.Connections = i.Connections
	if len(d.Connections) > 128 || len(i.Resources) > 512 {
		return d, errors.New("recovery supports at most 128 forwards and 512 tunnels")
	}
	for n := range d.Connections {

		c := d.Connections[n]
		if c.Enabled && (c.Engine == "haproxy" || c.Engine == "realm") {
			view, e := m.connectionView(ctx, c)
			if e != nil {
				return d, e
			}
			if view.SavedState == "different" {
				return d, fmt.Errorf("%s generated configuration has drifted; reconcile or import supported edits before backup", c.ID)
			}
		}
		d.Connections[n].Revision = ""
		d.Connections[n].Status = ""
	}
	for _, resource := range i.Resources {
		unit, e := boundedConfig(m.UnitDir, resource.ID+".service")
		if e != nil {
			return d, e
		}
		r := BackupResource{Name: resource.Name}
		if !resourceNameValid(r.Name) {
			r.Name = ""
		} // keep the native default name instead of inventing invalid metadata
		if resource.Engine == "gre" {
			g, e := recoveryGRE(resource.ID, unit)
			if e != nil {
				return d, fmt.Errorf("%s: %w", resource.ID, e)
			}
			r.GRE = &g
		} else {
			raw, e := boundedConfig(m.ConfigDir, resource.ID+".toml")
			if e != nil {
				return d, e
			}
			var gateway string
			if resource.Engine == "frp" && strings.Contains(raw, "transport.tls.force = false") && resource.Role == "entrance" {
				gateway, e = boundedConfig(m.ConfigDir, "gtm-gateway-"+strings.SplitN(resource.ID, "-", 4)[3]+".conf")
				if e != nil {
					return d, e
				}
			}
			reverse, e := recoveryReverse(resource.ID, raw, gateway)
			if e != nil {
				return d, fmt.Errorf("%s: %w", resource.ID, e)
			}
			input, e := reverse.Input()
			if e != nil {
				return d, e
			}
			rendered, e := m.call(ctx, "recovery-render", input, reverse.Engine)
			if e != nil {
				return d, e
			}
			if normalizeNative(rendered) != normalizeNative(raw) {
				return d, fmt.Errorf("%s has custom or unsupported settings; export stopped to avoid an incomplete backup", resource.ID)
			}
			if e = reverseRecoveryUnit(unit, filepath.Join(m.ConfigDir, resource.ID+".toml"), reverse, false); e != nil {
				return d, e
			}
			if gateway != "" {
				gatewayConfig, e := m.call(ctx, "recovery-render", input, "gateway")
				if e != nil {
					return d, e
				}
				if normalizeNative(gatewayConfig) != normalizeNative(gateway) {
					return d, errors.New("custom WSS gateway settings need manual migration")
				}
				gatewayUnit, e := boundedConfig(m.UnitDir, "gtm-gateway-"+reverse.Name+".service")
				if e != nil {
					return d, e
				}
				if e = reverseRecoveryUnit(gatewayUnit, filepath.Join(m.ConfigDir, "gtm-gateway-"+reverse.Name+".conf"), reverse, true); e != nil {
					return d, e
				}
			}
			r.Reverse = &reverse
		}
		d.Resources = append(d.Resources, r)
	}
	if traffic && m.Metrics != nil {
		v := m.Metrics.View()
		d.Traffic = &v
	}
	return d, nil
}

// Snapshot readers share the same flock as terminal writers. The public server
// has no access to these roots, and no caller supplies a filesystem path.
func (m *Manager) ExportBackup(ctx context.Context, in BackupInput) (BackupDownload, error) {
	if e := os.MkdirAll(m.ConfigDir, 0700); e != nil {
		return BackupDownload{}, e
	}
	lock, e := nodeLease(filepath.Join(m.ConfigDir, "manager.lock"))
	if e != nil {
		return BackupDownload{}, errors.New("manager is busy; retry backup")
	}
	defer lock.Close()
	d, e := m.recoverySnapshot(ctx, in.IncludeTraffic)
	if e != nil {
		return BackupDownload{}, e
	}
	d, _, e = validateRecovery(d, BackupInput{})
	if e != nil {
		return BackupDownload{}, e
	}
	archive, e := sealBackup(d, in.Password)
	return BackupDownload{Filename: "tunnel-manager-" + d.Created.Format("20060102-150405") + ".gtm-backup", Archive: archive}, e
}

func prepareRecovery(in BackupInput) (recoveryDocument, BackupReview, error) {
	var d recoveryDocument
	if e := openBackup(in.Archive, in.Password, &d); e != nil {
		return d, BackupReview{}, e
	}
	return validateRecovery(d, in)
}
func validateRecovery(d recoveryDocument, in BackupInput) (recoveryDocument, BackupReview, error) {
	v := BackupReview{Items: []BackupItem{}, Addresses: []string{}, Interfaces: []string{}, Certificates: []string{}, Blockers: []string{}}
	if d.Version != 1 || d.Created.IsZero() || d.Counter < 0 || d.Counter > 999999 || len(d.Connections) > 128 || len(d.Resources) > 512 || len(d.ManagerVersion) > 32 || len(d.Host) > 255 {
		return d, v, errors.New("unsupported recovery schema or resource count")
	}
	v.Created, v.Host, v.Version, v.Traffic = d.Created, d.Host, d.ManagerVersion, d.Traffic != nil
	addresses, interfaces, certificates := map[string]bool{}, map[string]bool{}, map[string]bool{}
	if len(in.Addresses) > 1024 || len(in.Interfaces) > 128 {
		return d, v, errors.New("too many migration mappings")
	}
	replacements := map[netip.Addr]string{}
	for a, b := range in.Addresses {
		x, e := netip.ParseAddr(a)
		y, e2 := netip.ParseAddr(b)
		if e != nil || e2 != nil || x.Zone() != "" || y.Zone() != "" || x.Is4() != y.Is4() || x.IsUnspecified() || y.IsUnspecified() || x.IsMulticast() || y.IsMulticast() {
			return d, v, errors.New("migration IPs must be literal addresses of the same family")
		}
		if _, ok := replacements[x]; ok {
			return d, v, errors.New("duplicate equivalent migration IP")
		}
		replacements[x] = b
	}
	for a, b := range in.Interfaces {
		if !recoveryInterface.MatchString(a) || !recoveryInterface.MatchString(b) {
			return d, v, errors.New("invalid migration interface")
		}
	}
	mapIP := func(ip string) string {
		addresses[ip] = true

		parsed, _ := netip.ParseAddr(ip)
		if replacement, ok := replacements[parsed]; ok {
			return replacement
		}
		return ip
	}
	ids := map[string]bool{}
	add := func(id, name, engine, summary string) error {
		if ids[id] {
			return errors.New("duplicate recovery resource")
		}
		ids[id] = true
		v.Items = append(v.Items, BackupItem{id, name, engine, summary})
		return nil
	}
	var rows []string
	for n := range d.Connections {
		c := &d.Connections[n]
		if !model.IDPattern.MatchString(c.ID) || c.ID == "F000000" {
			return d, v, errors.New("invalid recovery connection identity")
		}
		c.Bind = mapIP(c.Bind)
		for j := range c.Targets {
			c.Targets[j].IP = mapIP(c.Targets[j].IP)
		}
		if c.Interface != "any" {
			interfaces[c.Interface] = true
			if value, ok := in.Interfaces[c.Interface]; ok {
				c.Interface = value
			}
		}
		if c.Routing != nil && c.Routing.Certificate != "" {
			certificates[c.Routing.Certificate] = true
		}
		c.Revision = ""
		c.Status = ""
		emitted, e := c.Rows(c.ID)
		if e != nil || len(emitted) != 1 {
			return d, v, errors.New("invalid managed connection in backup")
		}
		rows = append(rows, emitted[0])
		var targets []string
		for _, target := range c.Targets {
			targets = append(targets, netip.AddrPortFrom(netip.MustParseAddr(target.IP), uint16(target.Port)).String())
		}
		if e = add(c.ID, c.Name, c.Engine, c.Protocol+" "+recoveryEndpoint(c.Bind, c.Ports)+" → "+strings.Join(targets, ", ")); e != nil {
			return d, v, e
		}
	}
	if _, _, e := model.ParseState(strings.Join(rows, "\n")); e != nil {
		return d, v, e
	}
	for n := range d.Resources {
		r := &d.Resources[n]
		if r.Name != "" && !resourceNameValid(r.Name) {
			return d, v, errors.New("invalid recovery display name")
		}
		if (r.GRE == nil) == (r.Reverse == nil) {
			return d, v, errors.New("one typed resource required")
		}
		if g := r.GRE; g != nil {
			g.Bind = mapIP(g.Bind)
			g.Remote = mapIP(g.Remote)
			a, e := netip.ParseAddr(g.Bind)
			b, e2 := netip.ParseAddr(g.Remote)
			if g.ID < 1 || g.ID > 250 || !oneOf(g.Role, "iran", "kharej") || e != nil || e2 != nil || a.Zone() != "" || b.Zone() != "" || a.Is4() != b.Is4() || a.IsUnspecified() || b.IsUnspecified() || a.IsMulticast() || b.IsMulticast() || g.MTU < 1280 || g.MTU > 1472 || (!a.Is4() && g.MTU > 1452) {
				return d, v, errors.New("invalid GRE recovery data")
			}
			name := r.Name
			if name == "" {
				name = fmt.Sprintf("gre-tun-%d", g.ID)
			}
			if e = add(fmt.Sprintf("gre-tun-%d", g.ID), name, "gre", g.Bind+" → "+g.Remote); e != nil {
				return d, v, e
			}
		} else {
			r.Reverse.Host = mapIP(r.Reverse.Host)
			r.Reverse.LocalIP = mapIP(r.Reverse.LocalIP)
			if _, e := r.Reverse.Input(); e != nil {
				return d, v, e
			}
			if r.Reverse.Engine == "rathole" && !noiseKey.MatchString(r.Reverse.Key) {
				return d, v, errors.New("missing rathole recovery key")
			}
			if r.Reverse.Certificate != "" && r.Reverse.Certificate != "-" {
				certificates[r.Reverse.Certificate] = true
			}
			summary := recoveryEndpoint(r.Reverse.Host, strconv.Itoa(r.Reverse.Control)) + " → " + recoveryEndpoint(r.Reverse.LocalIP, strconv.Itoa(r.Reverse.LocalPort))
			if r.Reverse.Role == "entrance" {
				summary = recoveryEndpoint(r.Reverse.Host, strconv.Itoa(r.Reverse.Control)) + " / " + recoveryEndpoint(r.Reverse.Host, strconv.Itoa(r.Reverse.Public))
			}
			name := r.Name
			if name == "" {
				name = r.Reverse.Name
			}
			if e := add("gtm-"+r.Reverse.Engine+"-"+r.Reverse.Role+"-"+r.Reverse.Name, name, r.Reverse.Engine, summary); e != nil {
				return d, v, e
			}
		}
	}
	if d.Traffic != nil {
		metrics := Metrics{view: cloneMetrics(*d.Traffic)}
		if e := metricsValid(metrics.view.Settings); e != nil {
			return d, v, e
		}
		if e := metrics.validateLedger(); e != nil {
			return d, v, e
		}
		for _, c := range metrics.view.Counters {
			if c.Received > maxTrafficBytes || c.Sent > maxTrafficBytes {
				return d, v, errors.New("traffic totals exceed supported precision")
			}
		}
		for _, points := range metrics.view.History {
			for _, p := range points {
				if p.Received > maxTrafficBytes || p.Sent > maxTrafficBytes || p.Time.IsZero() {
					return d, v, errors.New("invalid recovery traffic history")
				}
			}
		}
		for _, cycles := range metrics.view.Cycles {
			for _, p := range cycles {
				if p.Received > maxTrafficBytes || p.Sent > maxTrafficBytes || p.Start.After(p.End) {
					return d, v, errors.New("invalid recovery traffic cycle")
				}
			}
		}
		if metrics.view.Counters == nil {
			metrics.view.Counters = map[string]Traffic{}
		}
		d.Traffic = &metrics.view
	}
	for a := range addresses {
		v.Addresses = append(v.Addresses, a)
	}
	for a := range in.Addresses {
		key, _ := netip.ParseAddr(a)
		found := false
		for existing := range addresses {
			parsed, _ := netip.ParseAddr(existing)
			found = found || parsed == key
		}
		if !found {
			return d, v, errors.New("migration IP is not present in backup")
		}
	}
	for a := range in.Interfaces {
		if !interfaces[a] {
			return d, v, errors.New("migration interface is not present in backup")
		}
	}
	sort.Strings(v.Addresses)
	for a := range interfaces {
		v.Interfaces = append(v.Interfaces, a)
	}
	sort.Strings(v.Interfaces)
	for a := range certificates {
		v.Certificates = append(v.Certificates, a)
	}
	sort.Strings(v.Certificates)
	return d, v, nil
}

func (m *Manager) ReviewBackup(ctx context.Context, in BackupInput) (recoveryDocument, BackupReview, error) {
	d, v, e := prepareRecovery(in)
	if e != nil {
		return d, v, e
	}
	if e = os.MkdirAll(m.ConfigDir, 0700); e != nil {
		return d, v, e
	}
	lock, e := nodeLease(filepath.Join(m.ConfigDir, "manager.lock"))
	if e != nil {
		return d, v, errors.New("manager is busy; review again")
	}
	defer lock.Close()
	inventory, e := m.Inventory(ctx)
	if e != nil {
		return d, v, e
	}
	if len(inventory.Connections) > 0 || len(inventory.Resources) > 0 {
		v.Blockers = append(v.Blockers, "recoveryExisting")
	}
	entries, e := os.ReadDir(m.ConfigDir)
	if e != nil {
		return d, v, e
	}
	for _, entry := range entries {
		if (strings.HasPrefix(entry.Name(), "gtm-frp-") || strings.HasPrefix(entry.Name(), "gtm-rathole-")) && strings.HasSuffix(entry.Name(), ".toml") {
			if len(v.Blockers) == 0 {
				v.Blockers = append(v.Blockers, "recoveryExisting")
			}
			break
		}
	}
	revision, e := m.call(ctx, "recovery-revision", "")
	if e != nil {
		return d, v, e
	}
	v.Revision = strings.TrimSpace(revision)
	if !digestValid(v.Revision) {
		return d, v, errors.New("invalid server recovery revision")
	}
	metricRevision := uint64(0)
	if m.Metrics != nil {
		current := m.Metrics.View()
		metricRevision = current.Revision
		if in.IncludeTraffic && d.Traffic != nil && (current.Settings.Enabled || len(current.Counters) > 0 || len(current.Policies) > 0 || len(current.History) > 0 || len(current.Cycles) > 0) {
			v.Blockers = append(v.Blockers, "recoveryTrafficExisting")
		}
	}
	if in.IncludeTraffic && d.Traffic != nil && m.Metrics == nil {
		v.Blockers = append(v.Blockers, "recoveryTrafficUnavailable")
	}
	v.Revision += ":" + strconv.FormatUint(metricRevision, 10)
	return d, v, nil
}

func recoveryPayload(d recoveryDocument, revision string) (string, error) {
	var b strings.Builder
	b.WriteString(strings.SplitN(revision, ":", 2)[0] + "\n")
	fmt.Fprintf(&b, "I\t%d\n", d.Counter)
	for _, c := range d.Connections {
		c.Enabled = false
		rows, e := c.Rows(c.ID)
		if e != nil || len(rows) != 1 {
			return "", errors.New("invalid recovery row")
		}
		b.WriteString("C\t" + rows[0] + "\n")
	}
	for _, r := range d.Resources {
		id := ""
		if g := r.GRE; g != nil {
			id = fmt.Sprintf("gre-tun-%d", g.ID)
			fmt.Fprintf(&b, "G\t%d\t%s\t%s\t%s\t%d\n", g.ID, g.Role, g.Remote, g.Bind, g.MTU)
		} else {
			input, e := r.Reverse.Input()
			if e != nil {
				return "", e
			}
			b.WriteString("R\t" + input)
			id = "gtm-" + r.Reverse.Engine + "-" + r.Reverse.Role + "-" + r.Reverse.Name
		}
		if r.Name != "" {
			b.WriteString("N\t" + id + "\t" + r.Name + "\n")
		}
	}
	return b.String(), nil
}

func (m *Manager) RestoreBackup(ctx context.Context, in BackupInput) (any, error) {
	d, v, e := m.ReviewBackup(ctx, in)
	if e != nil {
		return nil, e
	}
	if in.Revision != v.Revision {
		return nil, errors.New("server changed; review the backup again")
	}
	if len(v.Blockers) > 0 {
		return nil, errors.New("restore needs an empty local managed installation and, when selected, an empty paused traffic ledger")
	}
	// Validate the full payload before the first write. A failed typed import never
	// changes existing rules or starts imported services.
	payload, e := recoveryPayload(d, v.Revision)
	if e != nil {
		return nil, e
	}
	if _, e = m.call(ctx, "recovery-import", payload); e != nil {
		return nil, e
	}
	result := map[string]any{"ok": true, "restored": len(v.Items), "paused": true}
	if in.IncludeTraffic && d.Traffic != nil {
		if m.Metrics == nil {
			result["warning"] = "recoveryTrafficUnavailable"
			return result, nil
		}
		m.Metrics.mu.Lock()
		defer m.Metrics.mu.Unlock()
		old := cloneMetrics(m.Metrics.view)
		next := cloneMetrics(*d.Traffic)
		next.Settings.Enabled = false
		next.Error = ""
		next.Revision = old.Revision + 1
		for id, c := range next.Counters {
			c.LastReceived = 0
			c.LastSent = 0
			next.Counters[id] = c
		}
		m.Metrics.view = next
		m.Metrics.signature = ""
		m.Metrics.nftActive = false
		if e = m.Metrics.save(); e != nil {
			m.Metrics.view = old
			result["warning"] = "recoveryTrafficSaveFailed"
		} else {
			result["traffic_restored"] = true
		}
	}
	return result, nil
}

func (m *Manager) backup(ctx context.Context, action string, in BackupInput) (any, error) {
	switch action {
	case "backup-export":
		return m.ExportBackup(ctx, in)
	case "backup-review":
		_, v, e := m.ReviewBackup(ctx, in)
		return v, e
	case "backup-restore":
		return m.RestoreBackup(ctx, in)
	}
	return nil, errors.New("unknown recovery action")
}
func recoveryEndpoint(ip, port string) string {
	if strings.Contains(ip, ":") {
		return "[" + ip + "]:" + port
	}
	return ip + ":" + port
}
