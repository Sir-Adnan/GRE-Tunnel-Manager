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
var nativeServer = regexp.MustCompile(`^server s([0-9]+) (\S+) weight ([0-9]+) check inter ([0-9]+)s fall ([0-9]+) rise ([0-9]+)(.*)$`)

// Import only changes that round-trip through the typed adapter. The caller
// re-renders and compares the ENTIRE submitted configuration before saving;
// unknown directives, executable hooks and inconsistent repeated values fail.
func importNative(original model.Connection, baseline, input string) (model.Connection, error) {
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
		if c.Engine == "haproxy" {
			if m := nativeTimeout.FindStringSubmatch(line); len(m) > 0 && nativeTimeout.MatchString(before[i]) {
				key := map[string]string{"connect": "connect", "client": "idle", "server": "idle", "queue": "queue", "check": "check_timeout", "client-fin": "fin", "server-fin": "fin", "tunnel": "tunnel"}[m[1]]
				old := nativeTimeout.FindStringSubmatch(before[i])
				if old[1] != m[1] {
					return c, errors.New("timeout directive identity cannot change")
				}
				c.Options[key] = m[2]
				continue
			}
			if m := nativeNumber.FindStringSubmatch(line); len(m) > 0 && strings.HasPrefix(before[i], m[1]+" ") {
				c.Options[m[1]] = m[2]
				continue
			}
			if strings.HasPrefix(line, "balance ") && strings.HasPrefix(before[i], "balance ") && c.Strategy != "failover" {
				c.Strategy = strings.TrimPrefix(line, "balance ")
				continue
			}
			if m := nativeStick.FindStringSubmatch(line); len(m) > 0 && nativeStick.MatchString(before[i]) {
				c.Options["stick_size"], c.Options["stick_expire"] = m[1], m[2]
				continue
			}
			if m := nativeServer.FindStringSubmatch(line); len(m) > 0 {
				old := nativeServer.FindStringSubmatch(before[i])
				if len(old) == 0 || old[1] != m[1] || old[7] != m[7] {
					return c, errors.New("unsupported server-line structure; use managed JSON")
				}
				n, _ := strconv.Atoi(m[1])
				if n < 1 || n > len(c.Targets) {
					return c, errors.New("invalid target index")
				}
				host, port, e := net.SplitHostPort(m[2])
				if e != nil {
					return c, e
				}
				p, e := strconv.Atoi(port)
				if e != nil {
					return c, e
				}
				w, e := strconv.Atoi(m[3])
				if e != nil {
					return c, e
				}
				c.Targets[n-1] = model.Target{IP: host, Port: p, Weight: w}
				c.Options["check_interval"], c.Options["check_fall"], c.Options["check_rise"] = m[4], m[5], m[6]
				continue
			}
		} else if c.Engine == "realm" {
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
