package control

import (
	"errors"
	"fmt"
	"maps"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// Closed scalar TOML subset; no includes, templates or executable configuration.
func parseRealmImport(text string) ([]model.Connection, error) {
	section := ""
	options := map[string]string{"log": "off"}
	protocol := "tcp"
	var cs []model.Connection
	seen := map[string]bool{}
	for n, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if oneOf(line, "[log]", "[network]", "[[endpoints]]") {
			if len(cs) > 0 && line != "[[endpoints]]" {
				return nil, errors.New("place global settings before endpoints")
			}
			section = line
			if section == "[[endpoints]]" {
				cs = append(cs, model.Connection{Name: fmt.Sprintf("realm-import-%d", len(cs)+1), Engine: "realm", Protocol: protocol, Bind: "0.0.0.0", Strategy: "single", SNAT: "masquerade", Interface: "any", Targets: []model.Target{}, Options: maps.Clone(options)})
				seen = map[string]bool{}
			}
			continue
		}
		m := assignment.FindStringSubmatch(line)
		if len(m) != 3 {
			return nil, fmt.Errorf("line %d: unsupported TOML syntax", n+1)
		}
		key, value := m[1], m[2]
		quoted := strings.HasPrefix(value, `"`)
		identity := section + key
		if seen[identity] {
			return nil, fmt.Errorf("duplicate field: %s", key)
		}
		seen[identity] = true
		if strings.HasPrefix(value, `"`) {
			v, e := strconv.Unquote(value)
			if e != nil {
				return nil, e
			}
			value = v
		}
		switch section {
		case "[log]":
			if !quoted {
				return nil, errors.New("log values must be quoted TOML strings")
			}
			if key == "level" {
				options["log"] = value
			} else if key != "output" || value != "stdout" {
				return nil, errors.New("only stdout log output is supported")
			}
		case "[network]":
			if len(cs) > 0 {
				return nil, errors.New("place global network settings before endpoints")
			}
			if oneOf(key, "no_tcp", "use_udp") {
				if quoted || !oneOf(value, "true", "false") {
					return nil, errors.New("invalid protocol flag")
				}
				options[key] = value
				continue
			}
			known := false
			for _, o := range model.RealmOptions {
				if o.Key == key {
					if quoted || oneOf(key, "log", "listen_transport", "remote_transport", "ws_host", "ws_path") {
						return nil, errors.New("use unquoted native network scalars; transport expressions belong in the form")
					}
					known = true
					options[key] = value
				}
			}
			if !known {
				return nil, fmt.Errorf("unsupported network setting: %s", key)
			}
		case "[[endpoints]]":
			if !quoted {
				return nil, errors.New("endpoint addresses must be quoted TOML strings")
			}
			c := &cs[len(cs)-1]
			switch key {
			case "listen":
				var e error
				c.Bind, c.Ports, e = haEndpoint(value, true)
				if e != nil {
					return nil, e
				}
			case "remote":
				host, port, e := haEndpoint(value, false)
				if e != nil {
					return nil, e
				}
				p, _ := strconv.Atoi(port)
				c.Targets = []model.Target{{IP: host, Port: p, Weight: 1}}
			default:
				return nil, fmt.Errorf("unsupported endpoint setting: %s; use managed JSON for multiple destinations", key)
			}
		default:
			return nil, errors.New("expected log, network or endpoints section")
		}
	}
	if options["no_tcp"] == "true" {
		protocol = "udp"
		if options["use_udp"] != "true" {
			return nil, errors.New("no_tcp requires use_udp")
		}
	} else if options["use_udp"] == "true" {
		protocol = "both"
	}
	delete(options, "no_tcp")
	delete(options, "use_udp")
	for i := range cs {
		cs[i].Protocol = protocol
		cs[i].Options = maps.Clone(options)
	}
	return cs, nil
}
