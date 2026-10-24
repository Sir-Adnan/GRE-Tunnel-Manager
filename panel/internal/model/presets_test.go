package model

import "testing"

func TestBuiltInPresetsUseSupportedAdapterContracts(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Presets() {
		if seen[p.ID] || p.ID == "" || p.Label["en"] == "" || p.Label["fa"] == "" || p.Help["en"] == "" || p.Help["fa"] == "" {
			t.Fatalf("invalid catalog identity/localization: %s", p.ID)
		}
		seen[p.ID] = true
		switch p.Engine {
		case "gre":
			if p.MTU < 1280 || p.MTU > 1452 {
				t.Fatal(p)
			}
		case "frp", "rathole":
			if !contains([]string{"tcp", "udp", "both"}, p.Protocol) || p.Mux == nil || !contains([]string{"tcp", "websocket", "wss", "quic"}, p.Transport) {
				t.Fatal(p)
			}
		default:
			for _, n := range []int{1, 2} {
				if p.MaxTargets > 0 && n > p.MaxTargets {
					continue
				}
				c := Connection{ID: "F000001", Name: "Profile", Engine: p.Engine, Protocol: p.Protocol, Bind: "192.0.2.10", Ports: "443", Strategy: p.Strategy, SNAT: "masquerade", Interface: "any", Enabled: true, Options: p.Options, Targets: []Target{{IP: "198.51.100.20", Port: 443, Weight: 1}}}
				if n == 1 {
					c.Strategy = "single"
				} else {
					c.Targets = append(c.Targets, Target{IP: "198.51.100.21", Port: 8443, Weight: 2})
				}
				rows, e := c.Rows(c.ID)
				if e != nil {
					t.Fatalf("%s/%d: %v", p.ID, n, e)
				}
				parsed, _, e := ParseState(rows[0])
				if e != nil || len(parsed) != 1 {
					t.Fatalf("profile roundtrip %s: %v", p.ID, e)
				}
			}
		}
	}
	if len(seen) != 21 {
		t.Fatal("catalog missing engine families")
	}
	counts := map[string]int{}
	for _, p := range Presets() {
		counts[p.Engine]++
	}
	for engine, count := range counts {
		if count != 3 {
			t.Fatalf("%s: want three setup presets, got %d", engine, count)
		}
	}
	first := Presets()
	first[0].Options["idle"] = "bad"
	if Presets()[0].Options["idle"] == "bad" {
		t.Fatal("catalog mutable across readers")
	}
}
