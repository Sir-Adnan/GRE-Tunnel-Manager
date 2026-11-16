package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

// inputRunner records the engine operation, its arguments and its stdin.
type inputRunner struct {
	answers map[string]string
	args    []string
	input   string
}

func (r *inputRunner) Run(_ context.Context, _ string, args []string, input string) (string, error) {
	if len(args) < 3 {
		return "", nil
	}
	if args[2] != "state" {
		r.args, r.input = args[2:], input
	}
	return r.answers[args[2]], nil
}

func TestFirewallStatusParsesTheEngineReport(t *testing.T) {
	out := strings.Join([]string{
		"revision\t" + strings.Repeat("a", 64),
		"nft\tavailable",
		"pending\t1800000000",
		"applied\t1",
		"ufw\tactive\tdeny\tdeny",
		"docker\tpresent",
		"backend\t4\tiptables\tnf_tables\tACCEPT\tACCEPT\t1",
		"backend\t4\tiptables-legacy\tlegacy\tDROP\tDROP\t0",
		"backend\t4\trm -rf\tlegacy\tDROP\tDROP\t0",
		"table\tinet abuse_defender",
		"uplink\tenp9s0",
		"uplink\tbad name",
		"ssh\t22",
		"ssh\t22",
		"auto-except\t10.202.10.10",
		"port\tF000001\ttcp\t8000:8003\ttagged",
		"port\tF000002\tudp\t443\t-",
		"port\tF000003\ttcp\t99999\topen",
		"counter\tgtm-F000001-allow\t12\t720",
		"counter\tgtm-private\t3\t180",
		"counter\tgtm-other\t1\t1",
		"setting\tprotect\tprivate\t1",
		"setting\texcept\t10.202.10.0/24",
		"setting\taccess\tF000001\tallow\t50\t20\t203.0.113.0/24,2001:db8::/32",
		"setting\tufw\tF000001",
	}, "\n")
	v := parseFirewallStatus(out)
	if !v.NFT || v.Applied == nil || !*v.Applied || v.Pending == nil || !v.Pending.Equal(time.Unix(1800000000, 0)) || !v.Docker {
		t.Fatalf("%+v", v)
	}
	if v.UFW != (FirewallUFW{State: "active", Incoming: "deny", Routed: "deny"}) || len(v.Backends) != 2 || v.Backends[1].Guard || v.Backends[1].Forward != "DROP" {
		t.Fatalf("%+v %+v", v.UFW, v.Backends)
	}
	if len(v.Uplinks) != 1 || len(v.SSH) != 1 || v.AutoExceptions[0] != "10.202.10.10" || v.Tables[0] != "inet abuse_defender" {
		t.Fatalf("%+v", v)
	}
	if len(v.Ports) != 2 || v.Ports[0].Port != "8000-8003" || v.Ports[0].UFW != "tagged" || v.Ports[1].UFW != "" {
		t.Fatalf("%+v", v.Ports)
	}
	if len(v.Counters) != 2 || v.Counters[0].Rule != "F000001-allow" || v.Counters[1].Rule != "private" {
		t.Fatalf("%+v", v.Counters)
	}
	s := v.Settings
	if !s.PrivateRanges || s.SMTP || s.Exceptions[0] != "10.202.10.0/24" || len(s.Access) != 1 || s.Access[0].PerIP != 50 || len(s.Access[0].Sources) != 2 || s.UFW[0] != "F000001" {
		t.Fatalf("%+v", s)
	}
}

func TestFirewallSettingsCanonicalizeAndValidate(t *testing.T) {
	cs := []model.Connection{{ID: "F000001", Name: "A", Bind: "0.0.0.0"}, {ID: "F000002", Name: "B", Bind: "2001:db8::1"}}
	s := FirewallSettings{
		Exceptions: []string{"10.202.10.7/24", "10.202.10.0/24", "2001:db8::5/128"},
		Access: []FirewallAccess{
			{ID: "F000001", Mode: "allow", Sources: []string{" 203.0.113.9/24 ", "2001:db8::/32"}, PerIP: 50},
			{ID: "F000002", Mode: "off"},
		},
		UFW: []string{"F000002"},
	}
	lines, e := s.lines(cs)
	if e != nil {
		t.Fatal(e)
	}
	want := "protect\tprivate\t0\nprotect\tsmtp\t0\nexcept\t10.202.10.0/24\nexcept\t2001:db8::5\naccess\tF000001\tallow\t50\t0\t203.0.113.0/24,2001:db8::/32\nufw\tF000002"
	if strings.Join(lines, "\n") != want {
		t.Fatalf("%q", strings.Join(lines, "\n"))
	}
	for name, bad := range map[string]FirewallSettings{
		"unknown":    {Access: []FirewallAccess{{ID: "F000009", Mode: "deny", Sources: []string{"1.2.3.4"}}}},
		"twice":      {UFW: []string{"F000001", "F000001"}},
		"family":     {Access: []FirewallAccess{{ID: "F000002", Mode: "allow", Sources: []string{"203.0.113.0/24"}}}},
		"empty":      {Access: []FirewallAccess{{ID: "F000001", Mode: "deny"}}},
		"everything": {Access: []FirewallAccess{{ID: "F000001", Mode: "deny", Sources: []string{"0.0.0.0/0"}}}},
		"mode":       {Access: []FirewallAccess{{ID: "F000001", Mode: "drop", Sources: []string{"1.2.3.4"}}}},
		"limit":      {Access: []FirewallAccess{{ID: "F000001", Mode: "off", Rate: 100001}}},
		"zone":       {Exceptions: []string{"fe80::1%eth0"}},
	} {
		if _, e := bad.lines(cs); e == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, e := (FirewallInput{Revision: "none", Seconds: 10}).validate(cs); e == nil {
		t.Fatal("a 10 s window was accepted")
	}
	if _, e := (FirewallInput{Revision: "x"}).validate(cs); e == nil {
		t.Fatal("a bad revision was accepted")
	}
}

func TestFirewallApplySendsTheRevisionAndValidatedLines(t *testing.T) {
	r := &inputRunner{answers: map[string]string{"state": row("F000001", "A", "192.0.2.1", true) + "\n"}}
	m := &Manager{Runner: r, UnitDir: t.TempDir()}
	in := FirewallInput{Revision: "none", Seconds: 60, Settings: FirewallSettings{SMTP: true, Access: []FirewallAccess{{ID: "F000001", Mode: "deny", Sources: []string{"198.51.100.0/24"}, Rate: 10}}}}
	if _, e := m.Execute(context.Background(), Request{Action: "firewall-apply", Firewall: in}); e != nil {
		t.Fatal(e)
	}
	if strings.Join(r.args, " ") != "firewall-apply 60" || r.input != "none\nprotect\tprivate\t0\nprotect\tsmtp\t1\naccess\tF000001\tdeny\t0\t10\t198.51.100.0/24\n" {
		t.Fatalf("%q %q", r.args, r.input)
	}
	in.Settings.Access[0].ID = "F000002"
	if _, e := m.Execute(context.Background(), Request{Action: "firewall-apply", Firewall: in}); e == nil {
		t.Fatal("an unknown connection was sent to the engine")
	}
	for _, action := range []string{"firewall-confirm", "firewall-revert"} {
		if _, e := m.Execute(context.Background(), Request{Action: action}); e != nil || r.args[0] != action {
			t.Fatal(action, r.args, e)
		}
	}
	if !ReadAction("firewall") || !PublicOperation("firewall-apply") || ReadAction("firewall-apply") {
		t.Fatal("firewall actions are not registered")
	}
}

func TestDemoFirewallRevertsAnUnconfirmedChange(t *testing.T) {
	d := NewDemo()
	ctx := context.Background()
	status := func() FirewallStatus {
		raw, e := d.Do(ctx, Request{Action: "firewall"})
		if e != nil {
			t.Fatal(e)
		}
		var v FirewallStatus
		if e := json.Unmarshal(raw, &v); e != nil {
			t.Fatal(e)
		}
		return v
	}
	v := status()
	in := FirewallInput{Revision: v.Revision, Seconds: 60, Settings: FirewallSettings{PrivateRanges: true, UFW: []string{"F000002"}}}
	if _, e := d.Do(ctx, Request{Action: "firewall-apply", Firewall: in}); e != nil {
		t.Fatal(e)
	}
	v = status()
	if v.Pending == nil || !v.Settings.PrivateRanges || v.Applied == nil {
		t.Fatalf("%+v", v)
	}
	if _, e := d.Do(ctx, Request{Action: "firewall-apply", Firewall: in}); e == nil {
		t.Fatal("a stale revision was accepted")
	}
	if _, e := d.Do(ctx, Request{Action: "firewall-revert"}); e != nil {
		t.Fatal(e)
	}
	if v = status(); v.Pending != nil || v.Settings.PrivateRanges {
		t.Fatalf("%+v", v)
	}
}
