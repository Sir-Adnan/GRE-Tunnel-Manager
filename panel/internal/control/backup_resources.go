package control

// These decoders recognize the generated adapters, not arbitrary system files.
// Reverse exports are additionally round-tripped through the Bash renderer.
import (
	"errors"
	"fmt"
	"net/netip"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var recoveryInterface = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,14}$`)
var recoveryGREStart = regexp.MustCompile(`(?m)^ExecStart=/sbin/ip( -6)? tunnel add (gre(?:-out-)?[0-9]+) mode (gre|ip6gre) remote ([0-9a-fA-F:.]+) local ([0-9a-fA-F:.]+) (ttl|hoplimit) 255 key ([0-9]+)$`)
var recoveryGREMTU = regexp.MustCompile(`(?m)^ExecStart=/sbin/ip link set dev [a-z0-9-]+ mtu ([0-9]+)$`)

func recoveryGRE(id, unit string) (GRE, error) {
	g := GRE{}
	if _, e := greConfigProjection(unit); e != nil {
		return g, e
	}
	a, b := recoveryGREStart.FindStringSubmatch(unit), recoveryGREMTU.FindStringSubmatch(unit)
	if a == nil || b == nil {
		return g, errors.New("unsupported GRE configuration; retain a separate copy of custom units")
	}
	g.ID, _ = strconv.Atoi(strings.TrimPrefix(id, "gre-tun-"))
	key, _ := strconv.Atoi(a[7])
	g.MTU, _ = strconv.Atoi(b[1])
	g.Remote, g.Bind = a[4], a[5]

	if strings.Contains(g.Remote, ":") {
		if a[1] != " -6" || a[3] != "ip6gre" || a[6] != "hoplimit" {
			return g, errors.New("unsupported GRE address family")
		}
	} else if a[1] != "" || a[3] != "gre" || a[6] != "ttl" {
		return g, errors.New("unsupported GRE address family")
	}
	g.Role = "kharej"
	iface := fmt.Sprintf("gre%d", g.ID)
	suffix := 1
	if strings.Contains(a[2], "gre-out-") {
		g.Role = "iran"
		iface = fmt.Sprintf("gre-out-%d", g.ID)
		suffix = 2
	}
	if key != g.ID || a[2] != iface {
		return g, errors.New("GRE key and identity differ")
	}
	// Exact command comparison prevents silently losing custom routes/hooks.
	expected := []string{a[0], fmt.Sprintf("ExecStart=/sbin/ip link set dev %s mtu %d", iface, g.MTU), "ExecStart=/sbin/ip link set dev " + iface + " up", fmt.Sprintf("ExecStart=/sbin/ip addr add 10.0.%d.%d/30 dev %s", g.ID, suffix, iface), fmt.Sprintf("ExecStart=/sbin/ip -6 addr add fd00:%d::%d/64 dev %s", g.ID, suffix, iface), "ExecStop=/sbin/ip link del dev " + iface, "ExecStopPost=-/sbin/ip link del dev " + iface}
	var actual []string
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "Exec") {
			actual = append(actual, line)
		}
	}
	if strings.Join(actual, "\n") != strings.Join(expected, "\n") {
		return g, errors.New("custom GRE commands need manual migration")
	}
	allowed := map[string]bool{"[Unit]": true, "[Service]": true, "[Install]": true, "Description=GRE Tunnel " + iface: true, "Wants=network-online.target": true, "After=network-online.target": true, "Type=oneshot": true, "RemainAfterExit=yes": true, "WantedBy=multi-user.target": true}
	for _, line := range expected {
		allowed[line] = true
	}
	if e := knownRecoveryUnit(unit, allowed); e != nil {
		return g, e
	}
	return g, nil
}

func knownRecoveryUnit(unit string, allowed map[string]bool) error {
	for _, line := range strings.Split(unit, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if !allowed[line] {
			return errors.New("custom service settings need manual migration")
		}
	}
	return nil
}
func reverseRecoveryUnit(unit, config string, r Reverse, gateway bool) error {
	binary := "rathole"
	suffix := " " + config
	if r.Engine == "frp" {
		binary = "frpc"
		if r.Role == "entrance" {
			binary = "frps"
		}
		suffix = " -c " + config
	}
	if gateway {
		binary = "haproxy"
		suffix = " -Ws -f " + config
	}
	allowed := map[string]bool{"[Unit]": true, "[Service]": true, "[Install]": true, "Wants=network-online.target": true, "After=network-online.target": true, "Type=simple": true, "Restart=on-failure": true, "RestartSec=5": true, "LimitNOFILE=65536": true, "NoNewPrivileges=yes": true, "ProtectHome=yes": true, "ProtectSystem=strict": true, "PrivateTmp=yes": true, "RestrictSUIDSGID=yes": true, "WantedBy=multi-user.target": true}
	if r.Engine == "rathole" {
		allowed["Description=Traffic Manager rathole reverse connection"] = true
		allowed["Environment=RUST_LOG=warn"] = true
	} else {
		allowed["Description=Traffic Manager "+r.Name] = true
	}
	if r.Engine == "frp" && r.Transport == "wss" && r.Role == "entrance" {
		if gateway {
			parent := "gtm-frp-entrance-" + r.Name + ".service"
			allowed["After="+parent] = true
			allowed["PartOf="+parent] = true
		} else {
			allowed["Wants=gtm-gateway-"+r.Name+".service"] = true
		}
	}
	count := 0
	for _, line := range strings.Split(unit, "\n") {
		if strings.HasPrefix(line, "ExecStart=") {
			command := strings.TrimPrefix(line, "ExecStart=")
			if !strings.HasSuffix(command, suffix) {
				return errors.New("custom reverse service command needs manual migration")
			}
			path := strings.TrimSuffix(command, suffix)
			if !safePath.MatchString(path) || filepath.Base(path) != binary {
				return errors.New("unrecognized reverse service executable")
			}
			allowed[line] = true
			count++
		}
	}
	if count != 1 {
		return errors.New("one generated reverse service command required")
	}
	return knownRecoveryUnit(unit, allowed)
}

func recoveryReverse(id, raw, gateway string) (Reverse, error) {
	p := strings.SplitN(strings.TrimPrefix(id, "gtm-"), "-", 3)
	if len(p) != 3 {
		return Reverse{}, errors.New("invalid reverse identity")
	}
	r := Reverse{Engine: p[0], Role: p[1], Name: p[2], Protocol: "tcp", Transport: "tcp", Host: "127.0.0.1", LocalIP: "127.0.0.1", LocalPort: 443, Public: 443, Group: p[2]}
	if _, e := redactReverse(raw); e != nil {
		return r, e
	}
	values := map[string][]string{}
	for _, line := range strings.Split(raw, "\n") {
		if a := assignment.FindStringSubmatch(strings.TrimSpace(line)); len(a) == 3 {
			values[a[1]] = append(values[a[1]], strings.Trim(a[2], `"`))
		}
	}
	get := func(key string) string {
		if len(values[key]) > 0 {
			return values[key][0]
		}
		return ""
	}
	number := func(key string) int { n, _ := strconv.Atoi(get(key)); return n }
	parseEndpoint := func(s string) (string, int, error) {
		a, e := netip.ParseAddrPort(s)
		if e != nil {
			return "", 0, errors.New("invalid reverse endpoint")
		}
		return a.Addr().String(), int(a.Port()), nil
	}
	var e error
	if r.Engine == "frp" {
		r.Token = get("auth.token")
		r.Mux = get("transport.tcpMux") == "true"
		if r.Role == "entrance" {
			r.Host = get("proxyBindAddr")
			r.Control = number("bindPort")
			a := publicPort.FindStringSubmatch(raw)
			if a == nil {
				return r, errors.New("unsupported FRP public ports")
			}
			r.Public, _ = strconv.Atoi(a[1])
			if get("quicBindPort") != "" {
				r.Transport = "quic"
			}
			if get("transport.tls.force") == "false" {
				r.Transport = "wss"
				r.Internal = r.Control
				bind := regexp.MustCompile(`(?m)^    bind (\S+) ssl crt (/[a-zA-Z0-9_./-]+)$`).FindStringSubmatch(gateway)
				if bind == nil {
					return r, errors.New("missing WSS gateway certificate reference")
				}
				r.Host, r.Control, e = parseEndpoint(bind[1])
				if e != nil {
					return r, e
				}
				r.Certificate = bind[2]
			}
		} else {
			r.Host = get("serverAddr")
			r.Control = number("serverPort")
			r.Public = number("remotePort")
			r.LocalIP = get("localIP")
			r.LocalPort = number("localPort")
			r.Protocol = get("type")
			r.Transport = get("transport.protocol")
			r.Certificate = get("transport.tls.trustedCaFile")
			if r.Transport == "wss" {
				r.Internal = 7001
			} // unused on destination, required by the shared typed contract
			if g := get("loadBalancer.group"); g != "" {
				r.Group = g
			}
			if get("name") != r.Name {
				return r, errors.New("FRP service and file identity differ")
			}
		}
	} else if r.Engine == "rathole" {
		r.Token = get("token")
		r.Key = get("remote_public_key")
		if r.Role == "entrance" {
			r.Key = get("local_private_key")
			r.Host, r.Control, e = parseEndpoint(get("bind_addr"))
			if e != nil {
				return r, e
			}
			if len(values["bind_addr"]) < 2 {
				return r, errors.New("missing rathole public service")
			}
			host, port, e := parseEndpoint(values["bind_addr"][1])
			if e != nil || host != r.Host {
				return r, errors.New("unsupported rathole service bind")
			}
			r.Public = port
		} else {
			r.Host, r.Control, e = parseEndpoint(get("remote_addr"))
			if e != nil {
				return r, e
			}
			r.LocalIP, r.LocalPort, e = parseEndpoint(get("local_addr"))
			if e != nil {
				return r, e
			}
			// Destination configs do not encode the public listener port. This field is
			// unused by their renderer; choose a valid distinct placeholder explicitly.
			for r.Public == r.Control || r.Public == r.LocalPort {
				r.Public++
			}
		}
		tcp, udp := false, false
		for _, v := range values["type"] {
			tcp = tcp || v == "tcp"
			udp = udp || v == "udp"
		}
		if udp {
			r.Protocol = "udp"
		}
		if udp && tcp {
			r.Protocol = "both"
		}
	} else {
		return r, errors.New("unsupported reverse engine")
	}
	if _, e = r.Input(); e != nil {
		return r, e
	}
	return r, nil
}
