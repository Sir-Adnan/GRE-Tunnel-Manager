package control

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestAddressReplaceArgs(t *testing.T) {
	ok := AddressInput{Old: "203.0.113.5", New: "203.0.113.10", Use: "local", Items: []string{"gre-tun-7", "F000001", "gtm-frp-entrance-web"}}
	args, e := ok.replaceArgs()
	if e != nil || strings.Join(args, " ") != "203.0.113.5 203.0.113.10 local gre-tun-7 F000001 gtm-frp-entrance-web" {
		t.Fatal(args, e)
	}
	v6 := AddressInput{Old: "2001:DB8::5", New: "2001:db8::10", Use: "remote", Items: []string{"all"}}
	if args, e = v6.replaceArgs(); e != nil || args[0] != "2001:db8::5" {
		t.Fatal("IPv6 is not canonical", args, e)
	}
	bad := []AddressInput{
		{Old: "203.0.113.5", New: "203.0.113.5", Use: "local", Items: []string{"all"}},
		{Old: "203.0.113.5", New: "2001:db8::1", Use: "local", Items: []string{"all"}},
		{Old: "0.0.0.0", New: "203.0.113.10", Use: "local", Items: []string{"all"}},
		{Old: "127.0.0.1", New: "203.0.113.10", Use: "local", Items: []string{"all"}},
		{Old: "203.0.113.5", New: "203.0.113.10", Use: "both", Items: []string{"all"}},
		{Old: "203.0.113.5", New: "203.0.113.10", Use: "local"},
		{Old: "203.0.113.5", New: "203.0.113.10", Use: "local", Items: []string{"gre-tun-7;reboot"}},
		{Old: "203.0.113.5", New: "203.0.113.10", Use: "local", Items: []string{"../etc/passwd"}},
	}
	for _, in := range bad {
		if _, e := in.replaceArgs(); e == nil {
			t.Fatal("accepted", in)
		}
	}
}

func TestAddressExtraArgs(t *testing.T) {
	args, e := AddressInput{Address: "203.0.113.40/32", Interface: "eth0"}.extraArgs()
	if e != nil || strings.Join(args, " ") != "203.0.113.40/32 eth0 -" {
		t.Fatal(args, e)
	}
	args, e = AddressInput{Address: "203.0.113.40/24", Interface: "eth1", Gateway: "203.0.113.1"}.extraArgs()
	if e != nil || strings.Join(args, " ") != "203.0.113.40/24 eth1 203.0.113.1" {
		t.Fatal(args, e)
	}
	for _, in := range []AddressInput{
		{Address: "203.0.113.40", Interface: "eth0"},
		{Address: "203.0.113.40/4", Interface: "eth0"},
		{Address: "127.0.0.2/32", Interface: "eth0"},
		{Address: "203.0.113.40/32", Interface: "any"},
		{Address: "203.0.113.40/32", Interface: "eth0; ip link"},
		{Address: "203.0.113.40/32", Interface: "eth0", Gateway: "2001:db8::1"},
	} {
		if _, e := in.extraArgs(); e == nil {
			t.Fatal("accepted", in)
		}
	}
}

func TestParseAddressRows(t *testing.T) {
	out := "local\t203.0.113.5\tgre\tgre-tun-7\t0\t1\n" +
		"remote\t198.51.100.70\tgre\tgre-tun-7\t-\t1\n" +
		"local\t203.0.113.10\tconnection\tF000001\t1\t1\n" +
		"local\t203.0.113.10\treverse\tgtm-frp-entrance-web\t1\t0\n" +
		"local\tnot-an-ip\tgre\tgre-tun-8\t1\t1\n" +
		"local\t203.0.113.10\tgre\tall\t1\t1\n" +
		"garbage\n"
	uses := parseAddressUses(out, map[string]string{"F000001": "Web"})
	if len(uses) != 4 || uses[0].Name != "GRE 7" || uses[0].Present || uses[2].Name != "Web" || uses[3].Editable {
		t.Fatal(uses)
	}
	extra := parseExtraAddresses("1\t203.0.113.40/32\teth0\t-\t1\t1\n2\t203.0.113.41/24\teth1\t203.0.113.1\t0\t0\n40\t203.0.113.42/32\teth0\t-\t1\t1\n")
	if len(extra) != 2 || extra[0].Gateway != "" || extra[1].Gateway != "203.0.113.1" || extra[1].Active {
		t.Fatal(extra)
	}
}

func TestAddressReportStaleAndSuggestion(t *testing.T) {
	uses := []AddressUse{
		{Use: "local", Address: "203.0.113.5", Kind: "gre", ID: "gre-tun-7"},
		{Use: "local", Address: "203.0.113.5", Kind: "connection", ID: "F000001"},
		{Use: "local", Address: "203.0.113.10", Kind: "connection", ID: "F000002", Present: true},
		{Use: "remote", Address: "198.51.100.70", Kind: "gre", ID: "gre-tun-7"},
	}
	host := []HostAddressView{{Interface: "docker0", Address: "172.17.0.1", Container: true}, {Interface: "eth0", Address: "2001:db8::10"}, {Interface: "eth0", Address: "203.0.113.10"}}
	r := addressReport(uses, []ExtraAddress{}, host, "eth0", "203.0.113.1", []string{"eth0"})
	if !slices.Equal(r.Stale, []string{"203.0.113.5"}) || r.Suggested != "203.0.113.10" {
		t.Fatal(r.Stale, r.Suggested)
	}
	if r = addressReport(uses[2:], nil, host, "eth0", "", nil); len(r.Stale) != 0 || r.Suggested != "" {
		t.Fatal(r)
	}
}

func TestDefaultGateway(t *testing.T) {
	table := "Iface\tDestination\tGateway \tFlags\n" +
		"eth1\t00000000\t0102A8C0\t0003\n" +
		"eth0\t0071CB00\t00000000\t0001\n" +
		"eth0\t00000000\t017100CB\t0003\n"
	if g := defaultGateway(strings.NewReader(table), "eth0"); g != "203.0.113.1" {
		t.Fatal(g)
	}
	if g := defaultGateway(strings.NewReader(table), "eth1"); g != "192.168.2.1" {
		t.Fatal(g)
	}
	if g := defaultGateway(strings.NewReader(table), "wg0"); g != "" {
		t.Fatal(g)
	}
}

func TestDemoAddressTools(t *testing.T) {
	d := NewDemo()
	ctx := context.Background()
	report := func() AddressReport {
		raw, e := d.Do(ctx, Request{Action: "addresses"})
		if e != nil {
			t.Fatal(e)
		}
		var r AddressReport
		if e = json.Unmarshal(raw, &r); e != nil {
			t.Fatal(e)
		}
		return r
	}
	r := report()
	if !slices.Equal(r.Stale, []string{"203.0.113.5"}) || r.Suggested != "203.0.113.10" {
		t.Fatal(r.Stale, r.Suggested)
	}
	if _, e := d.Do(ctx, Request{Action: "address-replace", Address: AddressInput{Old: "203.0.113.5", New: "203.0.113.99", Use: "local", Items: []string{"all"}}}); e == nil {
		t.Fatal("moved to an address that is not on the server")
	}
	raw, e := d.Do(ctx, Request{Action: "address-replace", Address: AddressInput{Old: "203.0.113.5", New: "203.0.113.10", Use: "local", Items: []string{"all"}}})
	if e != nil || !strings.Contains(string(raw), `result\tgre-tun-7\tdone`) {
		t.Fatal(string(raw), e)
	}
	if r = report(); len(r.Stale) != 0 {
		t.Fatal("still stale", r.Stale)
	}
	if _, e = d.Do(ctx, Request{Action: "address-extra-add", Address: AddressInput{Address: "203.0.113.40/32", Interface: "eth0"}}); e != nil {
		t.Fatal(e)
	}
	if r = report(); len(r.Extra) != 1 || !slices.ContainsFunc(r.Addresses, func(h HostAddressView) bool { return h.Address == "203.0.113.40" }) {
		t.Fatal(r.Extra)
	}
	if _, e = d.Do(ctx, Request{Action: "address-extra-delete", Address: AddressInput{ID: r.Extra[0].ID}}); e != nil {
		t.Fatal(e)
	}
}

// readdressRunner keeps one GRE tunnel's local address and answers the
// engine's readdress-check and readdress-apply verbs like src/addresses.sh.
type readdressRunner struct {
	local   string
	tamper  bool
	applied int
}

func readdressDigest(address string) string {
	if address == "203.0.113.5" {
		return strings.Repeat("a", 64)
	}
	return strings.Repeat("b", 64)
}

func (r *readdressRunner) Run(_ context.Context, _ string, args []string, _ string) (string, error) {
	switch args[2] {
	case "readdress-check":
		if r.local != args[3] {
			return "", errors.New("no tunnel uses the address")
		}
		if r.tamper {
			return strings.Repeat("c", 64) + "\n", nil
		}
		return readdressDigest(args[3]) + "\n", nil
	case "readdress-apply":
		if r.local != args[4] || readdressDigest(args[4]) != args[3] {
			return "", preflightChangedError{}
		}
		r.local = args[5]
		r.applied++
		return readdressDigest(args[5]) + "\n", nil
	}
	return "", errors.New("unexpected command " + args[2])
}

func TestNodeTaskReaddressConfirmAndRollback(t *testing.T) {
	now := time.Now()
	for _, decision := range []string{"confirm", "rollback", "tampered"} {
		runner := &readdressRunner{local: "203.0.113.5"}
		x := &NodeExecutor{Manager: &Manager{Runner: runner}, Directory: t.TempDir(), Now: func() time.Time { return now }}
		task := NodeTask{ID: strings.Repeat("a", 32), Stage: "prepare", Expires: now.Add(10 * time.Minute), Spec: NodeSpec{Kind: "readdress", Readdress: Readdress{Old: "203.0.113.5", New: "203.0.113.10", Use: "local"}}}
		res, e := x.Execute(context.Background(), task)
		if e != nil || res.State != "prepared" || res.Revision != strings.Repeat("a", 64) {
			t.Fatal(res, e)
		}
		task.Stage, task.Revision = "apply", res.Revision
		if res, e = x.Execute(context.Background(), task); e != nil || res.State != "applied" || runner.local != "203.0.113.10" {
			t.Fatal(res, e)
		}
		switch decision {
		case "confirm":
			task.Stage = "confirm"
			if res, _ = x.Execute(context.Background(), task); res.State != "committed" {
				t.Fatal(res)
			}
		case "rollback":
			task.Stage = "rollback"
			if res, _ = x.Execute(context.Background(), task); res.State != "rolled_back" || runner.local != "203.0.113.5" {
				t.Fatal("rollback did not restore the old address", res, runner.local)
			}
		case "tampered":
			runner.tamper = true
			task.Stage = "confirm"
			if res, _ = x.Execute(context.Background(), task); res.Code != "resource_changed" {
				t.Fatal(res)
			}
		}
	}
	bad := NodeSpec{Kind: "readdress", Readdress: Readdress{Old: "203.0.113.5", New: "203.0.113.10", Use: "local"}, GRE: GRE{ID: 1}}
	if bad.Validate() == nil {
		t.Fatal("readdress accepted extra GRE settings")
	}
	if (NodeSpec{Kind: "gre", GRE: GRE{ID: 1, Role: "iran", Remote: "198.51.100.2", Bind: "192.0.2.1", MTU: 1430}, Readdress: Readdress{Use: "local"}}).Validate() == nil {
		t.Fatal("GRE accepted a readdress block")
	}
}
