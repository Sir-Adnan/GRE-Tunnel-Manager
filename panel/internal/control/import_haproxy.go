package control

// Import a deliberately bounded TCP subset, not executable HAProxy files.
// Every accepted directive is represented in the typed model or explicitly
// reported as replaced by manager-owned process settings in the review.
import (
	"errors"
	"fmt"
	"maps"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

type haSection struct {
	kind, name string
	lines      []string
}

var haIdentifier = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}$`)

func haSeconds(value string) (string, error) {
	multiplier := 1
	if len(value) > 0 {
		switch value[len(value)-1] {
		case 's':
			value = value[:len(value)-1]
		case 'm':
			multiplier = 60
			value = value[:len(value)-1]
		case 'h':
			multiplier = 3600
			value = value[:len(value)-1]
		case 'd':
			multiplier = 86400
			value = value[:len(value)-1]
		}
	}
	n, e := strconv.Atoi(value)
	if e != nil || n < 0 || n > 604800 {
		return "", errors.New("unsupported duration")
	}
	if n*multiplier > 604800 {
		return "", errors.New("duration exceeds seven days")
	}
	return strconv.Itoa(n * multiplier), nil
}

func haEndpoint(value string, listener bool) (string, string, error) {
	host, port, e := net.SplitHostPort(value)
	if e != nil {
		return "", "", errors.New("use a literal IP:port or [IPv6]:port")
	}
	if listener && (host == "*" || host == "") {
		host = "0.0.0.0"
	}
	p, e := strconv.Atoi(port)
	if e != nil || p < 1 || p > 65535 {
		return "", "", errors.New("invalid endpoint port")
	}
	return host, strconv.Itoa(p), nil
}

func haSettings(lines []string, options map[string]string) error {
	paired := map[string]string{}
	seen := map[string]bool{}
	for _, line := range lines {
		f := strings.Fields(line)
		if len(f) == 0 {
			continue
		}
		identity := f[0]
		if len(f) > 1 && (f[0] == "timeout" || f[0] == "option") {
			identity += " " + f[1]
		}
		if seen[identity] {
			return fmt.Errorf("duplicate directive: %s", identity)
		}
		seen[identity] = true
		switch {
		case line == "mode tcp":
		case oneOf(line, "log global", "option tcplog", "option dontlognull", "option redispatch", "option tcpka", "option clitcpka", "option srvtcpka", "option dontlog-normal"):
			if line == "option tcplog" {
				options["log"] = "connections"
			}
			if line == "option dontlog-normal" {
				options["log"] = "errors"
			}
		case len(f) == 2 && oneOf(f[0], "retries", "maxconn"):
			options[f[0]] = f[1]
		case len(f) == 3 && f[0] == "timeout":
			key := map[string]string{"connect": "connect", "client": "idle", "server": "idle", "queue": "queue", "check": "check_timeout", "client-fin": "fin", "server-fin": "fin", "tunnel": "tunnel"}[f[1]]
			if key == "" {
				return fmt.Errorf("unsupported timeout: %s", f[1])
			}
			value, e := haSeconds(f[2])
			if e != nil {
				return e
			}
			if old, ok := paired[key]; ok && old != value {
				return fmt.Errorf("client/server %s values must match", key)
			}
			paired[key] = value
			options[key] = value
		default:
			return fmt.Errorf("unsupported defaults directive: %s", line)
		}
	}
	return nil
}

func haServer(line string, defaults []string) (model.Target, map[string]string, bool, error) {
	f := strings.Fields(line)
	var target model.Target
	if len(f) < 3 || f[0] != "server" || !haIdentifier.MatchString(f[1]) {
		return target, nil, false, errors.New("invalid server line")
	}
	host, port, e := haEndpoint(f[2], false)
	if e != nil {
		return target, nil, false, e
	}
	p, _ := strconv.Atoi(port)
	target = model.Target{IP: host, Port: p, Weight: 1}
	options := map[string]string{}
	check := false
	// Explicit server flags override default-server flags, as in HAProxy.
	parse := func(words []string) error {
		seen := map[string]bool{}
		for i := 0; i < len(words); i++ {
			key := words[i]
			identity := key
			if oneOf(key, "send-proxy", "send-proxy-v2") {
				identity = "proxy"
			}
			if seen[identity] {
				return errors.New("duplicate server option")
			}
			seen[identity] = true
			if key == "check" {
				check = true
				continue
			}
			if key == "send-proxy" {
				options["proxy"] = "v1"
				continue
			}
			if key == "send-proxy-v2" {
				options["proxy"] = "v2"
				continue
			}
			if i+1 >= len(words) {
				return errors.New("missing server option value")
			}
			i++
			value := words[i]
			switch key {
			case "weight":
				n, e := strconv.Atoi(value)
				if e != nil {
					return e
				}
				target.Weight = n
			case "inter", "slowstart":
				v, e := haSeconds(value)
				if e != nil {
					return e
				}
				options[map[string]string{"inter": "check_interval", "slowstart": "slowstart"}[key]] = v
			case "fall", "rise", "port", "maxconn":
				options[map[string]string{"fall": "check_fall", "rise": "check_rise", "port": "check_port", "maxconn": "server_maxconn"}[key]] = value
			default:
				return fmt.Errorf("unsupported server option: %s", key)
			}
		}
		return nil
	}
	if e = parse(defaults); e == nil {
		e = parse(f[3:])
	}
	return target, options, check, e
}

func parseHAImport(text string) ([]model.Connection, []string, error) {
	var sections []haSection
	for index, raw := range strings.Split(strings.ReplaceAll(text, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		if oneOf(f[0], "global", "defaults", "frontend", "backend") {
			if (oneOf(f[0], "global", "defaults") && len(f) != 1) || (oneOf(f[0], "frontend", "backend") && (len(f) != 2 || !haIdentifier.MatchString(f[1]))) {
				return nil, nil, fmt.Errorf("line %d: invalid section", index+1)
			}
			name := ""
			if len(f) == 2 {
				name = f[1]
			}
			for _, s := range sections {
				if s.kind == f[0] && s.name == name {
					return nil, nil, errors.New("duplicate section")
				}
			}
			sections = append(sections, haSection{kind: f[0], name: name})
			continue
		}
		if len(sections) == 0 {
			return nil, nil, fmt.Errorf("line %d: expected a section", index+1)
		}
		sections[len(sections)-1].lines = append(sections[len(sections)-1].lines, line)
	}
	options := map[string]string{"maxconn": "0", "server_maxconn": "0", "log": "off", "proxy": "off"}
	var serverDefaults []string
	backends := map[string]haSection{}
	var frontends []haSection
	warnings := []string{}
	for _, s := range sections {
		switch s.kind {
		case "global":
			for _, line := range s.lines {
				f := strings.Fields(line)
				switch {
				case len(f) == 2 && f[0] == "maxconn":
					options["maxconn"] = f[1]
				case f[0] == "log" && len(f) >= 3 && len(f) <= 5,
					len(f) == 2 && oneOf(f[0], "chroot", "user", "group"),
					len(f) >= 3 && f[0] == "stats" && oneOf(f[1], "socket", "timeout"), line == "daemon":
					warnings = append(warnings, "Manager process settings replace: "+line)
				default:
					return nil, nil, fmt.Errorf("unsupported global directive: %s", line)
				}
			}
		case "defaults":
			var settings []string
			for _, line := range s.lines {
				if strings.HasPrefix(line, "default-server ") {
					if serverDefaults != nil {
						return nil, nil, errors.New("duplicate default-server")
					}
					serverDefaults = strings.Fields(strings.TrimPrefix(line, "default-server "))
				} else {
					settings = append(settings, line)
				}
			}
			if e := haSettings(settings, options); e != nil {
				return nil, nil, e
			}
		case "backend":
			backends[s.name] = s
		case "frontend":
			frontends = append(frontends, s)
		}
	}
	if len(frontends) == 0 || len(frontends) > 32 {
		return nil, nil, errors.New("import requires 1–32 TCP frontends")
	}
	if len(frontends) > 1 {
		warnings = append(warnings, "managed-services-per-listener")
	}
	used := map[string]bool{}
	result := []model.Connection{}
	for _, front := range frontends {
		c := model.Connection{Name: front.name, Engine: "haproxy", Protocol: "tcp", Strategy: "single", SNAT: "masquerade", Interface: "any", Options: maps.Clone(options), Targets: []model.Target{}}
		backend := ""
		for _, line := range front.lines {
			f := strings.Fields(line)
			switch {
			case len(f) == 2 && f[0] == "bind":
				if c.Ports != "" {
					return nil, nil, errors.New("one bind per frontend is supported")
				}
				var e error
				c.Bind, c.Ports, e = haEndpoint(f[1], true)
				if e != nil {
					return nil, nil, e
				}
			case len(f) == 2 && f[0] == "default_backend":
				if backend != "" {
					return nil, nil, errors.New("duplicate default_backend")
				}
				backend = f[1]
			case line == "mode tcp":
			default:
				return nil, nil, fmt.Errorf("unsupported frontend directive: %s", line)
			}
		}
		back, ok := backends[backend]
		if !ok || c.Ports == "" {
			return nil, nil, errors.New("each frontend needs a bind and an existing default_backend")
		}
		used[backend] = true
		strategy := "roundrobin"
		var consistency map[string]string
		checks := -1
		hasTable, hasStick := false, false
		seenBackend := map[string]bool{}
		common := maps.Clone(c.Options)
		for _, line := range back.lines {
			f := strings.Fields(line)
			if f[0] != "server" {
				if seenBackend[f[0]] {
					return nil, nil, fmt.Errorf("duplicate backend directive: %s", f[0])
				}
				seenBackend[f[0]] = true
			}
			switch {
			case len(f) == 2 && f[0] == "balance":
				if !oneOf(f[1], "roundrobin", "leastconn", "source") {
					return nil, nil, errors.New("unsupported balancing method")
				}
				strategy = f[1]
			case line == "mode tcp", line == "hash-type consistent":
			case line == "stick on src":
				hasStick = true
			case len(f) == 7 && f[0] == "stick-table" && f[1] == "type" && oneOf(f[2], "ip", "ipv6") && f[3] == "size" && f[5] == "expire":
				size := f[4]
				multiplier := 1
				if strings.HasSuffix(size, "k") {
					multiplier = 1000
					size = strings.TrimSuffix(size, "k")
				}
				n, e := strconv.Atoi(size)
				if e != nil || n < 1 || n > 1000000 || n*multiplier > 1000000 {
					return nil, nil, errors.New("invalid stick table size")
				}
				expiry, e := haSeconds(f[6])
				if e != nil {
					return nil, nil, e
				}
				c.Options["stick"] = "source"
				hasTable = true
				c.Options["stick_size"] = strconv.Itoa(n * multiplier)
				c.Options["stick_expire"] = expiry
			case f[0] == "server":
				target, opts, check, e := haServer(line, serverDefaults)
				if e != nil {
					return nil, nil, e
				}
				enabled := 0
				if check {
					enabled = 1
				}
				if checks != -1 && checks != enabled {
					return nil, nil, errors.New("mixed per-server health-check settings cannot be represented")
				}
				checks = enabled
				// All shared adapter values must agree; never silently flatten differences.
				effective := map[string]string{}
				for _, o := range model.HAOptions {
					effective[o.Key] = o.Default
				}
				maps.Copy(effective, common)
				maps.Copy(effective, opts)
				shared := map[string]string{}
				for _, k := range []string{"check_interval", "check_fall", "check_rise", "check_port", "server_maxconn", "slowstart", "proxy"} {
					shared[k] = effective[k]
				}
				if consistency != nil && !maps.Equal(consistency, shared) {
					return nil, nil, errors.New("per-server options differ; use separate managed connections")
				}
				consistency = shared
				maps.Copy(c.Options, opts)
				c.Targets = append(c.Targets, target)
			default:
				return nil, nil, fmt.Errorf("unsupported backend directive: %s", line)
			}
		}
		if hasTable != hasStick {
			return nil, nil, errors.New("source affinity requires both stick-table and stick on src")
		}
		if checks == 0 {
			c.Options["check_mode"] = "off"
		}
		if len(c.Targets) > 1 {
			c.Strategy = strategy
		}
		if len(c.Name) > 40 {
			c.Name = c.Name[:40]
		}
		if _, e := c.Rows("F000000"); e != nil {
			return nil, nil, e
		}
		result = append(result, c)
	}
	if len(used) != len(backends) {
		return nil, nil, errors.New("unreferenced backend would be lost; remove it before import")
	}
	return result, warnings, nil
}
