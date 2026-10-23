package model

import (
	"strings"
	"testing"
)

func TestRoutingVersionedRoundTripAndClosedGrammar(t *testing.T) {
	c := Connection{Engine: "haproxy", Protocol: "tcp", Bind: "0.0.0.0", Ports: "443", Strategy: "single", Enabled: true, SNAT: "preserve", Interface: "any", Targets: []Target{{IP: "192.0.2.20", Port: 8443, Weight: 1}}, Options: map[string]string{}}
	for _, mode := range []string{"sni", "http", "https"} {
		cert := ""
		if mode == "https" {
			cert = "example"
		}
		c.Routing = &Routing{Version: 1, Mode: mode, Certificate: cert, Rules: []Route{{Host: "example.com", Target: 1}}}
		rows, e := c.Rows("F000001")
		if e != nil {
			t.Fatal(e)
		}
		if len(strings.Split(rows[0], "\t")) != 14 {
			t.Fatal(rows)
		}
		parsed, _, e := ParseState(rows[0])
		if e != nil || parsed[0].Routing.Mode != mode || parsed[0].Routing.Rules[0].Target != 1 {
			t.Fatal(e, parsed)
		}
	}
	for _, r := range []Routing{{Version: 2, Mode: "sni"}, {Version: 1, Mode: "https", Certificate: "../../etc/passwd"}, {Version: 1, Mode: "http", Rules: []Route{{Host: "x; lua-load attack", Target: 1}}}, {Version: 1, Mode: "sni", Rules: []Route{{Host: "example.com", Prefix: "/path", Target: 1}}}, {Version: 1, Mode: "http", Rules: []Route{{Host: "example.com", Prefix: "/~injection", Target: 1}}}, {Version: 1, Mode: "http", Rules: []Route{{Host: "example.com", Target: 2}}}} {
		if _, e := r.Encode(1); e == nil {
			t.Fatal("bad routing accepted", r)
		}
	}
}
func TestRealmExtendedProfileValidation(t *testing.T) {
	c := Connection{Engine: "realm", Protocol: "tcp", Bind: "0.0.0.0", Ports: "443", Strategy: "single", SNAT: "preserve", Interface: "any", Targets: []Target{{IP: "192.0.2.20", Port: 8443, Weight: 1}}, Options: map[string]string{"remote_transport": "ws", "ws_host": "example.com", "ws_path": "/relay"}}
	rows, e := c.Rows("F000001")
	if e != nil {
		t.Fatal(e)
	}
	parsed, _, e := ParseState(rows[0])
	if e != nil || parsed[0].Options["remote_transport"] != "ws" {
		t.Fatal(e, parsed)
	}
	c.Protocol = "both"
	if _, e := c.Rows("F000001"); e == nil {
		t.Fatal("WS over UDP accepted")
	}
	c.Options = map[string]string{"ipv6_only": "true"}
	if _, e := c.Rows("F000001"); e == nil {
		t.Fatal("IPv6-only on IPv4 accepted")
	}
	c.Protocol = "udp"
	c.Options = map[string]string{"send_mptcp": "true"}
	if _, e := c.Rows("F000001"); e == nil {
		t.Fatal("UDP MPTCP accepted")
	}
}
