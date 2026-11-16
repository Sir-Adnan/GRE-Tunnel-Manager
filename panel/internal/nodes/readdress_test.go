package nodes

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
)

// readdressFixture enrolls one operations Agent that reports version and addresses.
func readdressFixture(t *testing.T, version string, addresses []string) (*fixture, NodeChoice) {
	t.Helper()
	f := newFixture(t)
	id, _ := f.enroll(t, "remote")
	r := sample(t)
	r.Version = version
	r.Capabilities = []string{"inventory.read", control.NodeOperationCapability}
	var inv control.Inventory
	if e := json.Unmarshal(r.Inventory, &inv); e != nil {
		t.Fatal(e)
	}
	inv.Host.Addresses = addresses
	r.Inventory, _ = json.Marshal(inv)
	if e := post(context.Background(), transport(client(t, id)), f.s.URL+"/v1/report", r, &map[string]any{}); e != nil {
		t.Fatal(e)
	}
	return f, NodeChoice{ID: id.ID, Revision: f.h.Views().Nodes[0].Revision}
}

func problemCode(e error) string {
	var p *Problem
	if errors.As(e, &p) {
		return p.Code
	}
	return ""
}

func TestReaddressPlansBothEnds(t *testing.T) {
	f, remote := readdressFixture(t, "1.6.0", []string{"203.0.113.10"})
	in := ReaddressRequest{ID: strings.Repeat("d", 32), Changed: remote, Peer: NodeChoice{ID: "local"}, Old: "203.0.113.5", New: "203.0.113.10"}
	v, e := f.h.CreateReaddress(in)
	if e != nil {
		t.Fatal(e)
	}
	if v.Kind != "readdress" || v.Steps[0].Node != remote.ID || v.Steps[0].Service != "gre local 203.0.113.5 -> 203.0.113.10" || v.Steps[1].Service != "gre remote 203.0.113.5 -> 203.0.113.10" {
		t.Fatal(v)
	}
	if again, e := f.h.CreateReaddress(in); e != nil || again.ID != v.ID {
		t.Fatal("retry did not return the same job", e)
	}
	other := in
	other.New = "203.0.113.11"
	if _, e := f.h.CreateReaddress(other); problemCode(e) != "idempotency_conflict" {
		t.Fatal(e)
	}
	// The changed server prepares first; the peer applies only after it.
	w := workFor(t, f.h, remote.ID, nil)
	if w.Task == nil || w.Task.Spec.Kind != "readdress" || w.Task.Spec.Readdress.Use != "local" {
		t.Fatal(w)
	}
	busy := in
	busy.ID = strings.Repeat("e", 32)
	if _, e := f.h.CreateReaddress(busy); problemCode(e) != "node_busy" {
		t.Fatal(e)
	}
}

func TestReaddressRefusals(t *testing.T) {
	f, remote := readdressFixture(t, "1.5.3", []string{"203.0.113.10"})
	in := ReaddressRequest{ID: strings.Repeat("d", 32), Changed: remote, Peer: NodeChoice{ID: "local"}, Old: "203.0.113.5", New: "203.0.113.10"}
	if _, e := f.h.CreateReaddress(in); problemCode(e) != "agent_outdated" {
		t.Fatal("older Agent accepted", e)
	}
	f, remote = readdressFixture(t, "1.6.0-rc1", []string{"203.0.113.9"})
	in.Changed = remote
	if _, e := f.h.CreateReaddress(in); problemCode(e) != "address_missing" {
		t.Fatal("address not on the changed server accepted", e)
	}
	// The local server may be the changed one; its engine checks the address.
	in.Changed, in.Peer = NodeChoice{ID: "local"}, remote
	for _, bad := range [][2]string{{"203.0.113.5", "203.0.113.5"}, {"203.0.113.5", "2001:db8::1"}, {"10.0.0.1", "not-an-ip"}} {
		in.Old, in.New = bad[0], bad[1]
		if _, e := f.h.CreateReaddress(in); e == nil {
			t.Fatal("invalid change accepted", bad)
		}
	}
	in.Old, in.New = "203.0.113.5", "203.0.113.10"
	if _, e := f.h.CreateReaddress(in); e != nil {
		t.Fatal(e)
	}
	if len(f.h.Pairs()) != 1 {
		t.Fatal("refused requests were stored")
	}
}

func TestAtLeast(t *testing.T) {
	for v, want := range map[string]bool{"1.5.4": true, "1.5.10": true, "2.0.0": true, "1.5.3": false, "1.4.9": false, "1.5.4-rc1": true, "": false, "x.y.z": false} {
		if atLeast(v, "1.5.4") != want {
			t.Fatal(v)
		}
	}
}
