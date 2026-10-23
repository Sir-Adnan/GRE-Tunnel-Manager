package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

const maxConfigText = 65536

type ConfigInput struct {
	ID       string `json:"id"`
	Revision string `json:"revision"`
	Format   string `json:"format,omitempty"`
	Text     string `json:"text,omitempty"`
}
type ConfigFile struct {
	Name string `json:"name"`
	Path string `json:"path"`
	Text string `json:"text"`
	Kind string `json:"kind"`
}
type ConfigView struct {
	ID             string       `json:"id"`
	Revision       string       `json:"revision"`
	Engine         string       `json:"engine"`
	Files          []ConfigFile `json:"files"`
	Editor         string       `json:"editor,omitempty"`
	NativeEditable bool         `json:"native_editable"`
	SavedState     string       `json:"saved_state"`
}

func (m *Manager) renderConnection(ctx context.Context, c model.Connection) (string, error) {
	rows, e := c.Rows(c.ID)
	if e != nil || len(rows) != 1 {
		return "", errors.New("configuration must contain one managed port")
	}
	text, e := m.call(ctx, "config-render", rows[0]+"\n")
	if e != nil {
		return "", e
	}
	if len(text) > maxConfigText {
		return "", errors.New("configuration exceeds preview limit")
	}
	return text, nil
}
func (m *Manager) configConnection(ctx context.Context, in ConfigInput) (model.Connection, error) {
	if !model.IDPattern.MatchString(in.ID) || !digestValid(in.Revision) {
		return model.Connection{}, errors.New("select a managed connection and its revision")
	}
	cs, _, e := m.state(ctx)
	if e != nil {
		return model.Connection{}, e
	}
	for _, c := range cs {
		if c.ID == in.ID {
			if c.Revision != in.Revision {
				return c, errors.New("configuration changed; refresh before editing")
			}
			return c, nil
		}
	}
	return model.Connection{}, errors.New("connection not found")
}
func (m *Manager) Configuration(ctx context.Context, in ConfigInput) (ConfigView, error) {
	if model.IDPattern.MatchString(in.ID) {
		c, e := m.configConnection(ctx, in)
		if e != nil {
			return ConfigView{}, e
		}
		return m.connectionView(ctx, c)
	}
	if !ServiceOK(in.ID) || !(greID.MatchString(in.ID) || reverseID.MatchString(in.ID)) {
		return ConfigView{}, errors.New("unsupported managed resource")
	}
	unit, e := boundedConfig(m.UnitDir, in.ID+".service")
	if e != nil {
		return ConfigView{}, e
	}
	names, e := m.resourceNames()
	if e != nil {
		return ConfigView{}, e
	}
	r := Resource{ID: in.ID}
	applyResourceName(&r, []byte(unit), names[in.ID])
	if in.Revision != r.Revision {
		return ConfigView{}, errors.New("resource changed; refresh inventory")
	}
	v := ConfigView{ID: in.ID, Revision: r.Revision, SavedState: "saved", Files: []ConfigFile{}}
	if greID.MatchString(in.ID) {
		text, e := greConfigProjection(unit)
		if e != nil {
			return v, e
		}
		v.Engine = "gre"
		v.Files = append(v.Files, ConfigFile{Name: in.ID + ".commands.txt", Path: filepath.Join(m.UnitDir, in.ID+".service"), Text: text, Kind: "projection"})
		return v, nil
	}
	parts := strings.SplitN(strings.TrimPrefix(in.ID, "gtm-"), "-", 3)
	v.Engine = parts[0]
	// Only known generated units may select their fixed companion config.
	if !strings.Contains(unit, "Description=Traffic Manager") || !strings.Contains(unit, filepath.Join(m.ConfigDir, in.ID+".toml")) {
		return v, errors.New("unrecognized manager unit")
	}
	raw, e := boundedConfig(m.ConfigDir, in.ID+".toml")
	if e != nil {
		return v, e
	}
	text, e := redactReverse(raw)
	if e != nil {
		return v, e
	}
	v.Files = append(v.Files, ConfigFile{Name: in.ID + ".toml", Path: filepath.Join(m.ConfigDir, in.ID+".toml"), Text: text, Kind: "redacted"})
	return v, nil
}
func (m *Manager) connectionView(ctx context.Context, c model.Connection) (ConfigView, error) {
	text, e := m.renderConnection(ctx, c)
	if e != nil {
		return ConfigView{}, e
	}
	copy := c
	copy.ID = ""
	copy.Revision = ""
	copy.Status = ""
	b, e := json.MarshalIndent(copy, "", "  ")
	if e != nil {
		return ConfigView{}, e
	}
	path := "Generated owned firewall rules"
	state := "generated"
	if (c.Engine == "haproxy" || c.Engine == "realm") && m.ConfigDir == "" {
		path = filepath.Join("/etc/gre-manager/generated", c.ID+".conf") + " (demo)"
	}
	if (c.Engine == "haproxy" || c.Engine == "realm") && m.ConfigDir != "" {
		path = filepath.Join(m.ConfigDir, "generated", c.ID+".conf")
		saved, err := boundedConfig(m.ConfigDir, "generated/"+c.ID+".conf")
		state = "missing"
		if err == nil {
			state = "different"
			if saved == text {
				state = "matches"
			}
		} else if !os.IsNotExist(err) {
			return ConfigView{}, err
		}
	}
	return ConfigView{ID: c.ID, Revision: c.Revision, Engine: c.Engine, Files: []ConfigFile{{Name: c.ID + ".conf", Path: path, Text: text, Kind: "generated"}}, Editor: string(b), NativeEditable: c.Engine == "haproxy" || c.Engine == "realm", SavedState: state}, nil
}
func (m *Manager) ReviewConfiguration(ctx context.Context, in ConfigInput) (model.Connection, ConfigView, error) {
	original, e := m.configConnection(ctx, in)
	if e != nil {
		return original, ConfigView{}, e
	}
	if len(in.Text) > maxConfigText || !utf8.ValidString(in.Text) || strings.ContainsRune(in.Text, 0) {
		return original, ConfigView{}, errors.New("invalid configuration text")
	}
	next := original
	switch in.Format {
	case "json":
		next = model.Connection{}
		d := json.NewDecoder(strings.NewReader(in.Text))
		d.DisallowUnknownFields()
		if e = d.Decode(&next); e != nil {
			return original, ConfigView{}, errors.New("invalid managed configuration JSON")
		}
		var extra any
		if d.Decode(&extra) != io.EOF {
			return original, ConfigView{}, errors.New("one configuration object required")
		}
		if next.Engine != original.Engine || (next.ID != "" && next.ID != original.ID) || (next.Revision != "" && next.Revision != original.Revision) {
			return original, ConfigView{}, errors.New("engine and resource identity cannot change in the editor")
		}
		next.ID = original.ID
		next.Revision = original.Revision
		next.Status = ""
	case "native":
		baseline, err := m.renderConnection(ctx, original)
		if err != nil {
			return original, ConfigView{}, err
		}
		next, e = importNative(original, baseline, in.Text)
		if e != nil {
			return original, ConfigView{}, e
		}
	default:
		return original, ConfigView{}, errors.New("choose json or native format")
	}
	rows, e := next.Rows(next.ID)
	if e != nil || len(rows) != 1 {
		return original, ConfigView{}, errors.New("invalid configuration; keep exactly one managed port and supported values")
	}
	v, e := m.connectionView(ctx, next)
	if e != nil {
		return original, v, e
	}
	comparison := normalizeNative(v.Files[0].Text)
	if in.Format == "native" && original.Engine == "realm" && len(original.Options) == 0 {
		// v1 -> v3 adds these adapter defaults when the first option is edited.
		// The reviewed output still shows them; no user directive is ignored.
		for _, line := range []string{"tcp_keepalive_probe = 3", "send_proxy = false", "send_proxy_version = 2", "accept_proxy = false", "accept_proxy_timeout = 5"} {
			comparison = strings.ReplaceAll("\n"+comparison+"\n", "\n"+line+"\n", "\n")
			comparison = strings.TrimSpace(comparison)
		}
	}
	if in.Format == "native" && comparison != normalizeNative(in.Text) {
		return original, v, errors.New("native edit changes unsupported structure or inconsistent values; use the managed JSON editor or form")
	}
	return next, v, nil
}

// Fixed roots and filenames only; reject links, streams, replacements and large
// files. OpenRoot confines any intermediate resolution to the manager root.
func boundedConfig(dir, name string) (string, error) {
	root, e := os.OpenRoot(dir)
	if e != nil {
		return "", e
	}
	defer root.Close()
	if parent := filepath.Dir(name); parent != "." {
		p, err := root.Lstat(parent)
		if err != nil {
			return "", err
		}
		if !p.IsDir() {
			return "", errors.New("configuration directory must not be a link")
		}
	}
	before, e := root.Lstat(name)
	if e != nil {
		return "", e
	}
	if !before.Mode().IsRegular() || before.Size() > maxConfigText {
		return "", errors.New("configuration must be a bounded regular file")
	}
	f, e := root.Open(name)
	if e != nil {
		return "", e
	}
	defer f.Close()
	after, e := f.Stat()
	if e != nil || !os.SameFile(before, after) {
		return "", errors.New("configuration changed while reading")
	}
	b, e := io.ReadAll(io.LimitReader(f, maxConfigText+1))
	if e != nil || len(b) > maxConfigText || !utf8.Valid(b) {
		return "", errors.New("configuration is unreadable or too large")
	}
	return string(b), nil
}

var assignment = regexp.MustCompile(`^([a-zA-Z][a-zA-Z0-9_.]*)\s*=\s*(.+)$`)
var scalar = regexp.MustCompile(`^("[a-zA-Z0-9_ .:/\[\]+=\-]*"|true|false|[0-9]+|\[\{ single = [0-9]+ \}\])$`)
var tableName = regexp.MustCompile(`^\[(server|client)(\.(transport(\.(tcp|noise))?|services\."[a-zA-Z0-9_-]+"))?\]$`)

func redactReverse(raw string) (string, error) {
	allowed := strings.Fields("log.to bindAddr bindPort quicBindPort proxyBindAddr allowPorts auth.method auth.token transport.tls.force transport.tcpMux serverAddr serverPort transport.protocol transport.tls.enable transport.tls.trustedCaFile name type localIP localPort remotePort loadBalancer.group loadBalancer.groupKey healthCheck.type healthCheck.timeoutSeconds healthCheck.maxFailed healthCheck.intervalSeconds bind_addr remote_addr retry_interval nodelay keepalive_secs keepalive_interval pattern local_private_key remote_public_key token local_addr")
	secret := map[string]bool{"auth.token": true, "loadBalancer.groupKey": true, "token": true, "local_private_key": true}
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if line == "[[proxies]]" || tableName.MatchString(line) {
			lines = append(lines, line)
			continue
		}
		m := assignment.FindStringSubmatch(line)
		if len(m) != 3 || !oneOf(m[1], allowed...) {
			return "", errors.New("unsupported reverse configuration syntax; inspect locally")
		}
		if secret[m[1]] {
			lines = append(lines, m[1]+` = "[REDACTED]"`)
			continue
		}
		if !scalar.MatchString(m[2]) {
			return "", errors.New("unsupported reverse configuration value; inspect locally")
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n") + "\n", nil
}
func greConfigProjection(raw string) (string, error) {
	if !strings.Contains(raw, "Description=GRE Tunnel ") {
		return "", errors.New("unrecognized GRE unit")
	}
	var lines []string
	for _, line := range strings.Split(raw, "\n") {
		if strings.HasPrefix(line, "Exec") {
			if !(strings.HasPrefix(line, "ExecStart=/sbin/ip ") || strings.HasPrefix(line, "ExecStop=/sbin/ip ") || strings.HasPrefix(line, "ExecStopPost=-/sbin/ip ")) || strings.ContainsAny(line, ";$`%\\") {
				return "", errors.New("custom GRE commands cannot be previewed")
			}
			lines = append(lines, line)
		}
	}
	if len(lines) < 5 {
		return "", errors.New("incomplete GRE unit")
	}
	return "# Managed GRE network commands\n" + strings.Join(lines, "\n") + "\n", nil
}
