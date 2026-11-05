package model

import (
	"strings"
	"testing"
)

func kernel(ports string, targets ...Target) Connection {
	return Connection{Name: "", Engine: "nftables", Protocol: "tcp", Bind: "0.0.0.0", Ports: ports, Strategy: "single", Enabled: true, SNAT: "masquerade", Interface: "any", Targets: targets, Options: map[string]string{}}
}

func field(row string, i int) string { return strings.Split(row, "\t")[i] }

func TestKernelRangesAreOneRowWithMappedPorts(t *testing.T) {
	c := kernel("2000-2999, 8443", Target{IP: "203.0.113.5", Port: 443, Weight: 1})
	c.PortMode, c.RemotePorts = "map", "3000-3999,443"
	rows, e := c.Rows("F000000")
	if e != nil || len(rows) != 2 {
		t.Fatal(rows, e)
	}
	if field(rows[0], 5) != "2000-2999" || field(rows[0], 10) != "203.0.113.5:3000-3999@1" || field(rows[1], 10) != "203.0.113.5:443@1" || field(rows[0], 1) != "nftables-2000" {
		t.Fatal(rows)
	}
	c.PortMode = "same"
	rows, _ = c.Rows("F000000")
	if field(rows[0], 10) != "203.0.113.5:2000-2999@1" || field(rows[1], 10) != "203.0.113.5:8443@1" {
		t.Fatal(rows)
	}
	c.PortMode = ""
	rows, _ = c.Rows("F000000")
	if field(rows[0], 10) != "203.0.113.5:443@1" {
		t.Fatal(rows)
	}
	c.PortMode, c.RemotePorts = "map", "443,443"
	if rows, e = c.Rows("F000000"); e != nil || field(rows[0], 10) != "203.0.113.5:443@1" {
		t.Fatal("repeated remote port", rows, e)
	}
	c.PortMode = "same"
	rows, _ = c.Rows("F000000")
	parsed, _, e := ParseState(strings.Replace(rows[0], "F000000", "F000001", 1))
	if e != nil || parsed[0].Ports != "2000-2999" || parsed[0].Targets[0].PortLast != 2999 {
		t.Fatal(parsed, e)
	}
}

func TestRangeAndDomainRulesFailClosed(t *testing.T) {
	bad := []Connection{
		func() Connection {
			c := kernel("2000-2999", Target{IP: "203.0.113.5", Port: 3000, PortLast: 3500, Weight: 1})
			return c
		}(),
		func() Connection { c := kernel("1-4097", Target{IP: "203.0.113.5", Port: 1, Weight: 1}); return c }(),
		func() Connection {
			c := kernel("2000-2999,2500", Target{IP: "203.0.113.5", Port: 1, Weight: 1})
			return c
		}(),
		func() Connection {
			c := kernel("2000-2999", Target{IP: "0.0.0.0", Port: 1, Weight: 1})
			c.Bind = "203.0.113.5"
			return c
		}(),
		func() Connection {
			c := kernel("2000-2001", Target{IP: "203.0.113.5", Port: 3000, Weight: 1})
			c.Engine, c.PortMode, c.RemotePorts = "iptables", "map", "3000-3001"
			return c
		}(),
		func() Connection {
			c := kernel("2000-2001", Target{IP: "203.0.113.5", Port: 3000, Weight: 1})
			c.PortMode, c.RemotePorts = "map", "3000-3005"
			return c
		}(),
		func() Connection {
			c := kernel("2000-2001", Target{IP: "a.example", Port: 3000, Weight: 1})
			c.PortMode = "bogus"
			return c
		}(),
		func() Connection { c := kernel("443", Target{IP: "a_b.example", Port: 443, Weight: 1}); return c }(),
		func() Connection {
			c := kernel("443", Target{IP: "192.0.2.1", Port: 443, Weight: 1})
			c.Bind = "192.0.2.1"
			return c
		}(),
	}
	for i, c := range bad {
		if _, e := c.Rows("F000000"); e == nil {
			t.Fatalf("case %d accepted", i)
		}
	}
	// Relays expand ranges to single ports, never one range record.
	relay := kernel("8000-8002", Target{IP: "backend.example.org", Port: 443, Weight: 1})
	relay.Engine, relay.Options = "haproxy", map[string]string{}
	rows, e := relay.Rows("F000000")
	if e != nil || len(rows) != 3 || field(rows[2], 5) != "8002" || field(rows[0], 10) != "backend.example.org:443@1" {
		t.Fatal(rows, e)
	}
	if _, e := ParseTarget("[2001:db8::1]:2000-2999@3"); e != nil {
		t.Fatal(e)
	}
	for _, v := range []string{"2001:db8::1:443", "Example.org:443", "a.example:0", "1.2.3:443"} {
		if _, e := ParseTarget(v); e == nil {
			t.Fatal(v)
		}
	}
}
