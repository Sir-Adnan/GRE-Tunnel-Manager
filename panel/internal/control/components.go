package control

import (
	"context"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type componentProbe struct {
	mu    sync.Mutex
	until time.Time
	key   string
	value []Component
}
type engineCommand struct{ id, binary, argument string }

var engineCommands = []engineCommand{{"iptables", "iptables", "--version"}, {"nftables", "nft", "--version"}, {"haproxy", "haproxy", "-v"}, {"realm", "realm", "--version"}, {"frp", "frpc", "--version"}, {"frps", "frps", "--version"}, {"rathole", "rathole", "--version"}}
var engineVersion = regexp.MustCompile(`([0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})([-+~][a-zA-Z0-9.+~_-]{1,40})?\b`)

func parseEngineVersion(id, output string) string {
	if len(output) > 8192 {
		return ""
	}
	text := strings.TrimSpace(output)
	switch id {
	case "haproxy":
		if !strings.HasPrefix(text, "HAProxy version ") {
			return ""
		}
	case "realm":
		if !strings.HasPrefix(text, "realm ") {
			return ""
		}
	case "iptables":
		if !strings.HasPrefix(text, "iptables v") {
			return ""
		}
	case "nftables":
		if !strings.HasPrefix(text, "nftables v") {
			return ""
		}
	case "rathole":
		if !strings.HasPrefix(text, "rathole") {
			return ""
		}
		for _, line := range strings.Split(text, "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "Build Version:") {
				text = line
				break
			}
		}
	case "frp", "frps":
		if strings.ContainsAny(text, " \n\r\t") || !engineVersion.MatchString(text) {
			return ""
		}
	}
	m := engineVersion.FindStringSubmatch(text)
	if m == nil {
		return ""
	}
	return m[1] + m[2]
}

func compatibility(id, version string) string {
	if version == "" {
		return "unknown"
	}
	match := engineVersion.FindStringSubmatch(version)
	if match == nil {
		return "unknown"
	}
	base := match[1]
	switch id {
	case "realm":
		if base == "2.9.6" {
			return "pinned"
		}
		if strings.HasPrefix(base, "2.") {
			return "unverified"
		}
		return "unsupported"
	case "frp":
		if base == "0.71.1" {
			return "pinned"
		}
		return "unverified"
	case "rathole":
		if base == "0.5.0" {
			return "pinned"
		}
		return "unsupported"
	case "haproxy":
		parts := strings.Split(base, ".")
		major, _ := strconv.Atoi(parts[0])
		minor, _ := strconv.Atoi(parts[1])
		if major == 3 || (major == 2 && minor >= 4) {
			return "native_required"
		}
		return "unsupported"
	default:
		return "native_required"
	}
}

// Probe fixed commands only, on demand, cached for five minutes or until a binary
// changes. No version probe loop, remote request or additional service is added.
func (m *Manager) components(ctx context.Context) []Component {
	m.probes.mu.Lock()
	defer m.probes.mu.Unlock()
	paths := map[string]string{}
	var key strings.Builder
	for _, command := range engineCommands {
		path, e := lookupBinary(command.binary)
		if e != nil {
			continue
		}
		info, e := os.Stat(path)
		if e != nil {
			continue
		}
		paths[command.id] = path
		key.WriteString(path + ":" + strconv.FormatInt(info.Size(), 10) + ":" + strconv.FormatInt(info.ModTime().UnixNano(), 10) + ";")
	}
	_, socatError := lookupBinary("socat")
	key.WriteString(strconv.FormatBool(socatError == nil))
	if key.String() == m.probes.key && time.Now().Before(m.probes.until) {
		return append([]Component{}, m.probes.value...)
	}
	versions := map[string]string{}
	for _, command := range engineCommands {
		if path := paths[command.id]; path != "" {
			probeCtx, cancel := context.WithTimeout(ctx, time.Second)
			out, e := m.Runner.Run(probeCtx, path, []string{command.argument}, "")
			cancel()
			if e == nil {
				versions[command.id] = parseEngineVersion(command.id, out)
			}
		}
	}
	result := []Component{}
	for _, command := range engineCommands {
		if command.id == "frps" {
			continue
		}
		c := Component{ID: command.id, Installed: paths[command.id] != "", Version: versions[command.id], Compatibility: compatibility(command.id, versions[command.id])}
		if command.id == "haproxy" {
			c.Installed = c.Installed && socatError == nil
		}
		if command.id == "frp" {
			c.Installed = c.Installed && paths["frps"] != ""
			c.PeerVersion = versions["frps"]
			if c.Version == "" || c.PeerVersion == "" {
				c.Compatibility = "unknown"
			} else if c.Version != c.PeerVersion {
				c.Compatibility = "mismatch"
			}
		}
		result = append(result, c)
	}
	m.probes.key, m.probes.value = key.String(), result
	if ctx.Err() == nil {
		m.probes.until = time.Now().Add(5 * time.Minute)
	} else {
		m.probes.until = time.Time{}
	}
	return append([]Component{}, result...)
}
