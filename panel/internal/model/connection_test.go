package model

import (
	"reflect"
	"strings"
	"testing"
)

func TestRealmAdvancedRoundTrip(t *testing.T) {
	c := example()
	c.Engine, c.Protocol = "realm", "both"
	c.Options = map[string]string{"tcp_timeout": "8", "udp_timeout": "45", "tcp_keepalive_probe": "4", "send_proxy": "true", "log": "warn"}
	rows, e := c.Rows("F000001")
	if e != nil {
		t.Fatal(e)
	}
	parsed, _, e := ParseState(rows[0])
	if e != nil || len(parsed) != 1 {
		t.Fatal(e, rows)
	}
	if !reflect.DeepEqual(parsed[0].Options, c.Options) {
		t.Fatal("Realm options lost", parsed[0].Options)
	}
	if !strings.Contains(rows[0], "\t3\t") {
		t.Fatal(rows)
	}
}

func TestHTTPHealthClosedFieldsAndSeparatePort(t *testing.T) {
	c := example()
	c.Options = map[string]string{"check_mode": "http", "check_port": "8080", "check_path": "/ready/live", "check_host": "health.example.com", "check_status": "204"}
	rows, e := c.Rows("F000001")
	if e != nil {
		t.Fatal(e)
	}
	parsed, _, e := ParseState(rows[0])
	if e != nil || !reflect.DeepEqual(c.Options, parsed[0].Options) {
		t.Fatal(e, parsed)
	}
	for key, values := range map[string][]string{
		"check_mode": {"https", "off"}, "check_port": {"0", "443", "65536"},
		"check_path": {"health", "/x?secret=y", "/${PORT}", "/x\nbackend evil", "/x;log=off", "/x#comment", "/" + strings.Repeat("a", 128)},
		"check_host": {"a\r\nb", "a b", "$(id)", "${HOST}", "x;log=off"}, "check_status": {"199", "600", "2xx"},
	} {
		for _, value := range values {
			old := c.Options[key]
			c.Options[key] = value
			if _, e := c.Rows("F000001"); e == nil {
				t.Fatalf("accepted %s=%q", key, value)
			}
			c.Options[key] = old
		}
	}
}

func example() Connection {
	return Connection{Name: "", Engine: "haproxy", Protocol: "tcp", Bind: "0.0.0.0", Ports: "443", Strategy: "single", Enabled: true, SNAT: "masquerade", Interface: "any", Targets: []Target{{IP: "198.51.100.20", Port: 443, Weight: 1}}, Options: map[string]string{}}
}
func TestPortsBoundedAndUnique(t *testing.T) {
	for _, value := range []string{"0", "65536", "2-1", "1-40", "x", "443;id", "$(id)"} {
		if _, e := ParsePorts(value); e == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	v, e := ParsePorts("443,443 8000-8002")
	if e != nil || len(v) != 4 {
		t.Fatal(v, e)
	}
}
func TestRoundTripOptionsAndIPv6(t *testing.T) {
	c := example()
	c.Bind = "::"
	c.Targets = []Target{{IP: "2001:db8::2", Port: 8443, Weight: 2}}
	c.Options = map[string]string{"idle": "86400", "proxy": "v2", "log": "errors"}
	rows, e := c.Rows("F000001")
	if e != nil {
		t.Fatal(e)
	}
	parsed, raw, e := ParseState(rows[0] + "\n")
	if e != nil || len(parsed) != 1 {
		t.Fatal(e)
	}
	if parsed[0].Options["idle"] != "86400" || !strings.Contains(raw["F000001"], "\t2\t") {
		t.Fatal(parsed)
	}
	if parsed[0].Revision != Revision(rows[0]) {
		t.Fatal("unstable revision")
	}
}
func TestCapabilitiesFailClosed(t *testing.T) {
	cases := []func(*Connection){func(c *Connection) { c.Protocol = "udp" }, func(c *Connection) { c.Options = map[string]string{"raw": "exec sh"} }, func(c *Connection) { c.Options = map[string]string{"maxconn": "100001"} }, func(c *Connection) { c.Options = map[string]string{"idle": "$(id)"} }, func(c *Connection) { c.Targets[0].IP = "example.org" }, func(c *Connection) { c.Name = "test\nexec" }, func(c *Connection) { c.Interface = "eth0;id" }, func(c *Connection) { c.Targets = append(c.Targets, c.Targets[0]) }, func(c *Connection) { c.Engine = "nftables" }, func(c *Connection) { c.Bind = "198.51.100.20" }}
	for i, modify := range cases {
		c := example()
		modify(&c)
		if _, e := c.Rows("F000001"); e == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
}
func TestBatchAllocatesOneRowPerPort(t *testing.T) {
	c := example()
	c.Ports = "443,8443"
	rows, e := c.Rows("F000000")
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	if !strings.Contains(rows[1], "haproxy-8443") {
		t.Fatal(rows)
	}
	if _, e := c.Rows("F000001"); e == nil {
		t.Fatal("multiport edit accepted")
	}
}
