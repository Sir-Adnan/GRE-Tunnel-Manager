package control

import (
	"errors"
	"maps"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func normalizeNative(text string) string {
	var out []string
	for _, line := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

var nativeTimeout = regexp.MustCompile(`^timeout (connect|client|server|queue|check|client-fin|server-fin|tunnel) ([0-9]+)s$`)
var nativeNumber = regexp.MustCompile(`^(maxconn|retries) ([0-9]+)$`)
var nativeStick = regexp.MustCompile(`^stick-table type ipv6 size ([0-9]+) expire ([0-9]+)s$`)

// Import only changes that round-trip through the typed adapter. The caller
// re-renders and compares the ENTIRE submitted configuration before saving;
// unknown directives, executable hooks and inconsistent repeated values fail.
func importNative(original model.Connection, baseline, input string) (model.Connection, error) {
	if oneOf(original.Engine, "iptables", "nftables") {
		return importKernelNative(original, input)
	}
	if original.Engine == "haproxy" {
		return importGeneratedHA(original, baseline, input)
	}
	c := original
	c.Options = maps.Clone(original.Options)
	if c.Options == nil {
		c.Options = map[string]string{}
	}
	c.Targets = append([]model.Target{}, original.Targets...)
	before, after := strings.Split(normalizeNative(baseline), "\n"), strings.Split(normalizeNative(input), "\n")
	if len(before) != len(after) {
		return c, errors.New("native editor keeps the generated structure; use managed JSON for adding or removing fields")
	}
	for i, line := range after {
		if line == before[i] {
			continue
		}
		if c.Engine == "realm" {
			m, old := assignment.FindStringSubmatch(line), assignment.FindStringSubmatch(before[i])
			if len(m) == 3 && len(old) == 3 && m[1] == old[1] {
				key, value := m[1], strings.Trim(m[2], `"`)
				if key == "level" {
					c.Options["log"] = value
					continue
				}
				if key == "listen" {
					host, port, e := net.SplitHostPort(value)
					if e != nil {
						return c, e
					}
					c.Bind, c.Ports = host, port
					continue
				}
				if key == "remote" {
					host, port, e := net.SplitHostPort(value)
					if e != nil {
						return c, e
					}
					p, e := strconv.Atoi(port)
					if e != nil {
						return c, e
					}
					c.Targets[0].IP, c.Targets[0].Port = host, p
					continue
				}
				for _, option := range model.RealmOptions {
					if option.Key == key {
						c.Options[key] = value
						break
					}
				}
				if _, ok := c.Options[key]; ok {
					continue
				}
			}
		}
		return c, errors.New("unsupported native change; use the managed JSON editor for adapter fields")
	}
	return c, nil
}

// Separate engine values from fixed process/routing structure. This permits
// adding/removing optional directives while the final complete round-trip still
// rejects arbitrary syntax, executable directives and inconsistent copies.
func importGeneratedHA(original model.Connection, baseline, input string) (model.Connection, error) {
	c := original
	c.Options = maps.Clone(original.Options)
	if c.Options == nil {
		c.Options = map[string]string{}
	}
	c.Targets = append([]model.Target{}, original.Targets...)
	for k, v := range map[string]string{"maxconn": "0", "server_maxconn": "0", "fin": "0", "tunnel": "0", "stick": "off", "slowstart": "0", "proxy": "off"} {
		c.Options[k] = v
	}
	editable := func(line string) bool {
		return nativeTimeout.MatchString(line) || nativeNumber.MatchString(line) || strings.HasPrefix(line, "balance ") || nativeStick.MatchString(line) || line == "stick on src" || strings.HasPrefix(line, "server ")
	}
	remaining := func(text string) string {
		var lines []string
		for _, line := range strings.Split(normalizeNative(text), "\n") {
			if !editable(line) {
				lines = append(lines, line)
			}
		}
		return strings.Join(lines, "\n")
	}
	if remaining(baseline) != remaining(input) {
		return c, errors.New("fixed process and routing directives cannot change; import a TCP configuration or use the form")
	}
	var targets []model.Target
	var settings []string
	var maxconn string
	var shared map[string]string
	for _, line := range strings.Split(normalizeNative(input), "\n") {
		if !editable(line) {
			continue
		}
		if m := nativeNumber.FindStringSubmatch(line); m != nil && m[1] == "maxconn" {
			if maxconn != "" {
				if maxconn != m[2] {
					return c, errors.New("global and frontend maxconn must match")
				}
				continue
			}
			maxconn = m[2]
		}
		if m := nativeStick.FindStringSubmatch(line); m != nil {
			c.Options["stick"] = "source"
			c.Options["stick_size"], c.Options["stick_expire"] = m[1], m[2]
			continue
		}
		if line == "stick on src" {
			continue
		}
		if strings.HasPrefix(line, "balance ") {
			if c.Strategy != "failover" {
				c.Strategy = strings.TrimPrefix(line, "balance ")
			}
			continue
		}
		if strings.HasPrefix(line, "server ") {
			if c.Strategy == "failover" {
				line = strings.TrimSuffix(line, " backup")
			}
			target, opts, check, e := haServer(line, nil)
			if e != nil {
				return c, e
			}
			for _, key := range []string{"check_interval", "check_fall", "check_rise", "check_port", "server_maxconn", "slowstart", "proxy"} {
				if _, ok := opts[key]; !ok {
					for _, o := range model.HAOptions {
						if o.Key == key {
							opts[key] = o.Default
						}
					}
				}
			}
			if !check {
				opts["check_mode"] = "off"
			} else if c.Options["check_mode"] != "http" {
				opts["check_mode"] = "tcp"
			}
			if shared != nil && !maps.Equal(shared, opts) {
				return c, errors.New("server options must be consistent")
			}
			shared = opts
			targets = append(targets, target)
			continue
		}
		settings = append(settings, line)
	}
	if e := haSettings(settings, c.Options); e != nil {
		return c, e
	}
	if len(targets) == 0 {
		return c, errors.New("at least one server is required")
	}
	// Routed backends repeat server definitions. Keep their original targets;
	// final comparison validates that every repeated definition stays consistent.
	if c.Routing == nil {
		c.Targets = targets
		if len(targets) == 1 {
			c.Strategy = "single"
		}
	}
	maps.Copy(c.Options, shared)
	return c, nil
}
