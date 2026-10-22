package control

import (
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

var proxyAddress = regexp.MustCompile(`(?m)^proxyBindAddr = "([0-9a-fA-F:.]+)"$`)
var publicPort = regexp.MustCompile(`(?m)^allowPorts = \[\{ single = ([0-9]+) \}\]$`)
var reverseBind = regexp.MustCompile(`(?m)^bind_addr = "([0-9a-fA-F:.\[\]]+)"$`)

func readReverseListener(directory string, r *Resource) {
	if r.Role != "entrance" {
		return
	}
	data, e := os.ReadFile(filepath.Join(directory, r.ID+".toml"))
	if e != nil {
		return
	}
	text := string(data)
	if r.Engine == "frp" {
		a, p := proxyAddress.FindStringSubmatch(text), publicPort.FindStringSubmatch(text)
		if a == nil || p == nil {
			return
		}
		ip, e := netip.ParseAddr(a[1])
		if e != nil {
			return
		}
		port, e := strconv.Atoi(p[1])
		if e != nil || port < 1 || port > 65535 {
			return
		}
		r.Bind = ip.String()
		r.Port = port
		r.Protocol = "both"
	} else if r.Engine == "rathole" {
		matches := reverseBind.FindAllStringSubmatch(text, -1)
		if len(matches) < 2 {
			return
		}
		ap, e := netip.ParseAddrPort(matches[1][1])
		if e != nil {
			return
		}
		r.Bind = ap.Addr().String()
		r.Port = int(ap.Port())
		r.Protocol = "tcp"
		udp := strings.Contains(text, "type = \"udp\"")
		tcp := strings.Contains(text, "type = \"tcp\"")
		if udp {
			r.Protocol = "udp"
		}
		if tcp && udp {
			r.Protocol = "both"
		}
	}
}
