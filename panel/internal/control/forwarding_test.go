package control

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/notify"
)

func domainRow() string {
	c := model.Connection{ID: "F000003", Name: "D", Engine: "nftables", Protocol: "tcp", Bind: "0.0.0.0", Ports: "443", Strategy: "roundrobin", Enabled: true, SNAT: "masquerade", Interface: "any", Targets: []model.Target{{IP: "a.example", Port: 443, Weight: 1}}, Options: map[string]string{}}
	rows, e := c.Rows(c.ID)
	if e != nil {
		panic(e)
	}
	return rows[0]
}

func TestDomainConnectionsUseResolvedTargetsForHealthAndFailover(t *testing.T) {
	r := &scriptRunner{answers: map[string]string{
		"state":     domainRow() + "\n",
		"dns-cache": "name\ta.example\t4\t1700000000\t5\tall\t203.0.113.10,203.0.113.11\nrecord\tF000003\t203.0.113.10:443@1,203.0.113.11:443@1\nrecord\tF000009\tbad\n",
	}}
	m := &Manager{Runner: r, UnitDir: t.TempDir()}
	inv, e := m.Inventory(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	c := inv.Connections[0]
	if len(inv.DNS) != 1 || inv.DNS[0].Addresses[1] != "203.0.113.11" || len(c.Resolved) != 2 || c.Resolved[1].IP != "203.0.113.11" {
		t.Fatal(inv.DNS, c.Resolved)
	}
	targets := healthTargets(inv)
	if len(targets) != 2 || targets[0].Address != "203.0.113.10" || targets[1].Indexes[0] != 2 {
		t.Fatal(targets)
	}
	if ic := connectionsOf(inv)["F000003"]; len(ic.targets) != 2 {
		t.Fatal(ic)
	}
	// Literal connections never call the DNS view.
	r2 := &scriptRunner{answers: map[string]string{"state": row("F000001", "A", "192.0.2.1", true) + "\n"}}
	if _, e := (&Manager{Runner: r2, UnitDir: t.TempDir()}).Inventory(context.Background()); e != nil || strings.Contains(strings.Join(r2.calls, ","), "dns-cache") {
		t.Fatal(r2.calls, e)
	}
}

func TestDemoDNSPoliciesAndActiveResolversFollowTheCurrentContract(t *testing.T) {
	d := NewDemo()
	ctx := context.Background()
	if _, e := d.Do(ctx, Request{Action: "dns-apply", DNS: DNSInput{Servers: []string{"1.1.1.1"}}}); e != nil {
		t.Fatal(e)
	}
	if d.extras().dns.Active[0] != "1.1.1.1" {
		t.Fatal(d.extras().dns)
	}
	cs, _, e := model.ParseState(domainRow())
	if e != nil {
		t.Fatal(e)
	}
	d.inventory.Connections = cs
	if _, e = d.Do(ctx, Request{Action: "dns-policy", DNS: DNSInput{Policy: &DNSPolicy{Name: "a.example", Every: 15, Mode: "first"}}}); e != nil {
		t.Fatal(e)
	}
	if len(d.inventory.Connections[0].Resolved) != 1 || d.inventory.DNS[0].Every != 15 || d.inventory.DNS[0].Mode != "first" {
		t.Fatal(d.inventory.Connections, d.inventory.DNS)
	}
}

func TestServerDNSParsingValidationAndResolverTest(t *testing.T) {
	v := parseServerDNS("mode\tresolved\nmanaged\t1\ncurrent\t127.0.0.53\nupstream\t1.1.1.1 8.8.8.8 x\nservers\t1.1.1.1 8.8.8.8\noriginal\t10.0.0.2\n")
	if v.Mode != "resolved" || !v.Managed || len(v.Upstream) != 2 || v.Original[0] != "10.0.0.2" || len(v.Presets) < 10 {
		t.Fatal(v)
	}
	if parseServerDNS("mode\tweird\n").Mode != "unknown" {
		t.Fatal("unknown mode")
	}
	for _, bad := range [][]string{{}, {"127.0.0.1"}, {"0.0.0.0"}, {"fe80::1"}, {"224.0.0.1"}, {"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4"}, {"1.1.1.1; reboot"}} {
		if _, e := (DNSInput{Servers: bad}).servers(4); e == nil {
			t.Fatal(bad)
		}
	}
	if s, e := (DNSInput{Servers: []string{"10.202.10.10", "1.1.1.1", "1.1.1.1"}}).servers(4); e != nil || len(s) != 2 {
		t.Fatal(s, e)
	}
	saved := dnsQuery
	defer func() { dnsQuery = saved }()
	dnsQuery = func(_ context.Context, server, _ string) error {
		if server == "192.0.2.53" {
			return errors.New("timeout")
		}
		return nil
	}
	results := testResolvers(context.Background(), []string{"1.1.1.1", "192.0.2.53"})
	if results[0].OK != 3 || results[0].Error != "" || results[1].OK != 0 || results[1].Error != "timeout" {
		t.Fatal(results)
	}
	all, _ := dnsTestServers(DNSInput{})
	if len(all) != 20 {
		t.Fatal(len(all))
	}
	m := &Manager{Runner: &scriptRunner{answers: map[string]string{"dns-resolve": "203.0.113.5\n203.0.113.6\n"}}}
	res, e := m.dns(context.Background(), Request{Action: "dns-resolve", DNS: DNSInput{Name: "a.example"}})
	if e != nil || len(res.(DNSResolve).Addresses) != 2 {
		t.Fatal(res, e)
	}
	if _, e := m.dns(context.Background(), Request{Action: "dns-resolve", DNS: DNSInput{Name: "a.example;id"}}); e == nil {
		t.Fatal("bad name accepted")
	}
	if _, e := m.dns(context.Background(), Request{Action: "dns-policy", DNS: DNSInput{Policy: &DNSPolicy{Name: "a.example", Every: 0, Mode: "all"}}}); e == nil {
		t.Fatal("bad policy accepted")
	}
	if got := parseDNSRefresh("a.example\t4\tchanged\t203.0.113.9\nbad\tline\n"); len(got) != 1 || got[0].Status != "changed" {
		t.Fatal(got)
	}
}

func TestPortfwRulesImportAsRangeRecords(t *testing.T) {
	cs, warnings, e := parsePortfwImport("1\t2001-2003,2010\t203.0.113.50\t3001-3003,8080\tboth\n2\t443\tbackend.example\t443\ttcp\n3\t5000-5002\t203.0.113.51\t6000,6001,6002\tudp\n", "nftables")
	if e != nil || len(cs) != 3 || len(warnings) != 2 {
		t.Fatal(cs, warnings, e)
	}
	if cs[0].Ports != "2001-2003,2010" || cs[0].RemotePorts != "3001-3003,8080" || cs[1].Strategy != "roundrobin" || cs[2].Ports != "5000-5002" || cs[2].RemotePorts != "6000-6002" {
		t.Fatal(cs)
	}
	rows, e := cs[0].Rows("F000000")
	if e != nil || len(rows) != 2 || !strings.Contains(rows[0], "\t2001-2003\t") || !strings.Contains(rows[0], "203.0.113.50:3001-3003@1") {
		t.Fatal(rows, e)
	}
	if _, _, e := parsePortfwImport("1\t2001-2003\t203.0.113.50\t3001-3003\ttcp\n", "iptables"); e == nil {
		t.Fatal("shifted iptables import accepted")
	}
	if _, _, e := parsePortfwImport("1\t2001-2003\t203.0.113.50\t3001\ttcp\n", "nftables"); e == nil {
		t.Fatal("count mismatch accepted")
	}
	if _, _, e := parsePortfwImport("", "nftables"); e == nil {
		t.Fatal("empty import accepted")
	}
}

func TestOrderSafeChangeAndProtection(t *testing.T) {
	dir := t.TempDir()
	o, e := NewOperations(dir)
	if e != nil {
		t.Fatal(e)
	}
	r := &scriptRunner{answers: map[string]string{
		"state":             row("F000001", "A", "192.0.2.1", true) + "\n",
		"history":           "revision\t" + strings.Repeat("b", 64) + "\ntotal\t1\npoint\t20260102T030000-1-1.tsv\nrow\t" + row("F000001", "A", "192.0.2.1", true) + "\n",
		"recovery-revision": strings.Repeat("b", 64) + "\n",
	}}
	m := &Manager{Runner: r, UnitDir: t.TempDir(), Ops: o}
	if _, e := m.order(Request{Action: "ui-order-save", Order: OrderInput{List: "connections", IDs: []string{"F000002", "F000001"}}}); e != nil {
		t.Fatal(e)
	}
	got, _ := m.order(Request{Action: "ui-order"})
	if got.(map[string][]string)["connections"][0] != "F000002" {
		t.Fatal(got)
	}
	for _, bad := range []OrderInput{{List: "other", IDs: []string{"a"}}, {List: "gre", IDs: []string{"a", "a"}}, {List: "gre", IDs: []string{"a b"}}} {
		if _, e := m.order(Request{Action: "ui-order-save", Order: bad}); e == nil {
			t.Fatal(bad)
		}
	}
	// Protection: monitor off + notify off on an existing connection.
	if _, e := m.Execute(context.Background(), Request{Action: "health-protect", Selected: []Selection{{ID: "F000001"}}, Protect: &Protection{Monitor: false, Notify: false, EnableHealth: true}}); e != nil {
		t.Fatal(e)
	}
	s := o.Health.Settings()
	if !s.Enabled || len(s.Ignore) != 1 || s.Quiet[0] != "F000001" {
		t.Fatal(s)
	}
	if _, e := m.Execute(context.Background(), Request{Action: "health-protect", Selected: []Selection{{ID: "F000001"}}, Protect: &Protection{Monitor: true, Notify: true, Failover: true}}); e != nil {
		t.Fatal(e)
	}
	if s = o.Health.Settings(); len(s.Ignore) != 0 || len(s.Quiet) != 0 || len(s.Failover) != 0 {
		t.Fatal("single-destination forward cannot fail over", s)
	}
	// Safe change: arm, then a timeout restores the point while nothing else changed.
	if _, e := m.Execute(context.Background(), Request{Action: "enable", SafeMinutes: 1}); e == nil {
		t.Fatal("1 minute accepted")
	}
	now := time.Now().UTC()
	if e := m.armSafe(context.Background(), Request{Action: "update", SafeMinutes: 5, Connection: model.Connection{Name: "A", Ports: "443"}}, now, "receipt\t20260102T030000-1-1.tsv\t"+strings.Repeat("b", 64)); e != nil {
		t.Fatal(e)
	}
	again, _ := NewOperations(dir)
	if p := again.pendingSafe(); p == nil || p.Point != "20260102T030000-1-1.tsv" || !p.Deadline.Equal(now.Add(5*time.Minute)) {
		t.Fatal("pending change not persisted", p)
	}
	m.checkSafe(context.Background(), now.Add(time.Minute))
	if o.pendingSafe() == nil {
		t.Fatal("reverted early")
	}
	m.checkSafe(context.Background(), now.Add(6*time.Minute))
	if o.pendingSafe() != nil || !strings.Contains(strings.Join(r.calls, ","), "history-restore 20260102T030000-1-1.tsv "+strings.Repeat("b", 64)) {
		t.Fatal(r.calls)
	}
	events := o.Notify.View().Events
	if len(events) == 0 || events[len(events)-1].Kind != notify.KindChangeReverted {
		t.Fatal(events)
	}
	// A later change by someone else cancels the revert instead.
	_ = m.armSafe(context.Background(), Request{Action: "update", SafeMinutes: 5}, now, "receipt\t20260102T030000-1-1.tsv\t"+strings.Repeat("b", 64))
	r.answers["recovery-revision"] = strings.Repeat("c", 64)
	r.calls = nil
	m.checkSafe(context.Background(), now.Add(6*time.Minute))
	if o.pendingSafe() != nil || strings.Contains(strings.Join(r.calls, ","), "history-restore") {
		t.Fatal(r.calls)
	}
	// Quiet owners stay in the center but are not delivered.
	o.Notify.SetQuiet([]string{"F000001"})
	ev := o.Notify.Emit(notify.Event{Kind: notify.KindDown, Owner: "F000001"})
	if ev.Delivery != "" {
		t.Fatal(ev)
	}
	_ = health.Defaults()
}
