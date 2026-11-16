package control

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func TestConnectionPathParsesStagesAndDrops(t *testing.T) {
	out := "engine\tnftables\t1\nstage\tback\t203.0.113.20\t1500\t2100000\nstage\tnew\t-\t12\t720\nstage\tout\t203.0.113.20\t900\t81000\n" +
		"stage\tbogus\t-\t1\t1\nstage\tout\t203.0.113.21\tx\t0\ndrop\tiptables-legacy\ndrop\tsomething\nstage\tblocked\t-\t11\t660\n"
	path := parseConnectionPath("F000001", out)
	if path.Engine != "nftables" || !path.Enabled {
		t.Fatalf("engine %+v", path)
	}
	if len(path.Stages) != 4 || path.Stages[0] != (PathStage{Key: "back", Address: "203.0.113.20", Packets: 1500, Bytes: 2100000}) || path.Stages[1].Address != "" {
		t.Fatalf("stages %+v", path.Stages)
	}
	if len(path.Drops) != 1 || path.Drops[0] != "iptables-legacy" {
		t.Fatalf("drops %+v", path.Drops)
	}
	if empty := parseConnectionPath("F000002", "engine\trealm\t0\n"); empty.Enabled || len(empty.Stages) != 0 || empty.Drops == nil {
		t.Fatalf("disabled %+v", empty)
	}
}

func TestDemoPathGrowsAndFollowsTheFirewallRepair(t *testing.T) {
	d := NewDemo()
	sample := func(id string) ConnectionPath {
		raw, e := d.Do(t.Context(), Request{Action: "connection-path", Health: HealthInput{Owner: id}})
		if e != nil {
			t.Fatal(e)
		}
		var p ConnectionPath
		if e := json.Unmarshal(raw, &p); e != nil {
			t.Fatal(e)
		}
		return p
	}
	before := sample("F000004")
	if len(before.Drops) != 1 {
		t.Fatalf("legacy drop expected first: %+v", before)
	}
	if _, e := d.Do(t.Context(), Request{Action: "firewall-repair"}); e != nil {
		t.Fatal(e)
	}
	after := sample("F000004")
	if len(after.Drops) != 0 {
		t.Fatalf("repair should clear the drop: %+v", after)
	}
	relay := sample("F000001")
	if relay.Engine != "haproxy" || relay.Stages[0].Key != "clients" {
		t.Fatalf("relay %+v", relay)
	}
	if _, e := d.Do(t.Context(), Request{Action: "connection-path", Health: HealthInput{Owner: "F00000x"}}); e == nil {
		t.Fatal("invalid ID accepted")
	}
}

func TestDemoCreateRejectsAReservedPort(t *testing.T) {
	d := NewDemo()
	create := func(port, protocol string) error {
		_, e := d.Do(t.Context(), Request{Action: "create", Connection: model.Connection{Name: "probe", Engine: "nftables", Protocol: protocol, Bind: "0.0.0.0", Ports: port, Strategy: "single", Enabled: true, SNAT: "masquerade", Interface: "any", Targets: []model.Target{{IP: "198.51.100.9", Port: 443, Weight: 1}}, Options: map[string]string{}}})
		return e
	}
	if e := create("443", "both"); e == nil || !strings.Contains(e.Error(), "Port is reserved by managed connection F000001") {
		t.Fatalf("443 should be reserved: %v", e)
	}
	if e := create("9443", "tcp"); e != nil {
		t.Fatal(e)
	}
}
