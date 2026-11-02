package control

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func TestQuotaBlockingOptInResetAndRestart(t *testing.T) {
	ctx := context.Background()
	r := &fakeRunner{}
	cs, _, _ := model.ParseState(stateFixture())
	inv := Inventory{Connections: cs}
	path := filepath.Join(t.TempDir(), "metrics.json")
	m, _ := NewMetrics(r, path)
	policy := TrafficPolicy{Limit: 150, Direction: "received", StopOnLimit: true}
	if _, e := m.Change(ctx, "metrics-policy", TrafficChange{ID: cs[0].ID, Policy: policy}, inv); e == nil {
		t.Fatal("unmeasured automatic pause allowed")
	}
	if _, e := m.Configure(ctx, MetricsSettings{Enabled: true, Interval: 15}, inv); e != nil {
		t.Fatal(e)
	}
	if _, e := m.Change(ctx, "metrics-policy", TrafficChange{ID: cs[0].ID, Revision: m.View().Revision, Policy: policy}, inv); e != nil {
		t.Fatal(e)
	}
	r.counter = 160
	if e := m.Tick(ctx, inv); e != nil {
		t.Fatal(e)
	}
	if !m.View().Blocked[cs[0].ID] {
		t.Fatal("quota did not block")
	}
	policy.Limit = 10000
	if _, e := m.Change(ctx, "metrics-policy", TrafficChange{ID: cs[0].ID, Revision: m.View().Revision, Policy: policy}, inv); e != nil || m.View().Blocked[cs[0].ID] {
		t.Fatal("raising quota did not resume", e)
	}
	policy.Limit = 150
	if _, e := m.Change(ctx, "metrics-policy", TrafficChange{ID: cs[0].ID, Revision: m.View().Revision, Policy: policy}, inv); e != nil || !m.View().Blocked[cs[0].ID] {
		t.Fatal("lowering quota did not reapply", e)
	}
	last := strings.Join(r.calls, "\n")
	for _, part := range []string{"ct direction original drop", "ct direction reply drop"} {
		if !strings.Contains(last, part) {
			t.Fatal(part, last)
		}
	}
	if _, e := m.Configure(ctx, MetricsSettings{Enabled: false, Interval: 15}, inv); e == nil {
		t.Fatal("disabled protection without consent")
	}
	m, e := NewMetrics(r, path)
	if e != nil {
		t.Fatal(e)
	}
	if !m.View().Policies[cs[0].ID].StopOnLimit || !quotaReached(m.View().Counters[cs[0].ID], policy) {
		t.Fatal("lost policy")
	}
	if _, e = m.Change(ctx, "metrics-reset", TrafficChange{ID: cs[0].ID, Revision: m.View().Revision}, inv); e != nil {
		t.Fatal(e)
	}
	if m.View().Blocked[cs[0].ID] {
		t.Fatal("reset did not resume")
	}
	r.counter = 1000
	if e := m.Tick(ctx, inv); e != nil {
		t.Fatal(e)
	}
	policy.StopOnLimit = false
	if _, e = m.Change(ctx, "metrics-policy", TrafficChange{ID: cs[0].ID, Revision: m.View().Revision, Policy: policy}, inv); e != nil || m.View().Blocked[cs[0].ID] {
		t.Fatal("policy removal did not resume", e)
	}
}

func TestQuotaFailedPublicationDoesNotClaimAnAppliedBlock(t *testing.T) {
	ctx := context.Background()
	r := &fakeRunner{}
	cs, _, _ := model.ParseState(stateFixture())
	inv := Inventory{Connections: cs}
	m, _ := NewMetrics(r, filepath.Join(t.TempDir(), "ledger.json"))
	if _, e := m.Configure(ctx, MetricsSettings{Enabled: true, Interval: 15}, inv); e != nil {
		t.Fatal(e)
	}
	before := m.View()
	r.counter = 1000
	r.failApply = true
	_, e := m.Change(ctx, "metrics-policy", TrafficChange{ID: cs[0].ID, Revision: before.Revision, Policy: TrafficPolicy{Limit: 1, Direction: "received", StopOnLimit: true}}, inv)
	if e == nil || m.View().Blocked[cs[0].ID] || m.View().Policies[cs[0].ID].StopOnLimit {
		t.Fatal("failed apply reported protection", e, m.View())
	}
	if m.View().Counters[cs[0].ID].Received < 1000 {
		t.Fatal("failed policy lost captured bytes")
	}
}

func TestQuotaRulesAreScopedBidirectionalAndDoNotFlush(t *testing.T) {
	cs, _, _ := model.ParseState(stateFixture())
	cs[0].Enabled = false // established DNAT must stay blocked even after disable.
	inv := Inventory{Connections: cs, Resources: []Resource{{ID: "gre-tun-1", Engine: "gre", Interface: "gre1"}, {ID: "gtm-frp-entrance-example", Engine: "frp", Role: "entrance", Bind: "0.0.0.0", Port: 443, Protocol: "tcp"}}}
	rules := metricsRules(inv, MetricsSettings{Enabled: true}, map[string]bool{"F000001": true, "gre-tun-1": true, "gtm-frp-entrance-example": true})
	for _, part := range []string{"ct original proto-dst 28443", `iifname "gre1" drop`, `oifname "gre1" drop`, "meta l4proto tcp th dport 443 drop", "meta l4proto tcp th sport 443 drop"} {
		if !strings.Contains(rules, part) {
			t.Fatal(part, rules)
		}
	}
	if strings.Contains(rules, "flush") || strings.Contains(rules, "conntrack -D") {
		t.Fatal(rules)
	}
	// An advisory policy must never produce a block, regardless of consumption.
	v := MetricsView{Counters: map[string]Traffic{"F000001": {Received: 999}}, Policies: map[string]TrafficPolicy{"F000001": {Limit: 1, Direction: "total"}}}
	if len(quotaBlocks(v)) != 0 {
		t.Fatal("advisory changed behavior")
	}
	if validTrafficPolicy(TrafficPolicy{Direction: "total", StopOnLimit: true}) {
		t.Fatal("zero limit autostop")
	}
}

func TestQuotaWildcardAddressFamiliesRespectListenerScope(t *testing.T) {
	for _, c := range []model.Connection{{ID: "F000001", Engine: "haproxy", Enabled: true, Bind: "0.0.0.0", Protocol: "tcp", Ports: "443"}, {ID: "F000002", Engine: "realm", Enabled: true, Bind: "::", Protocol: "udp", Ports: "51820", Options: map[string]string{"ipv6_only": "true"}}} {
		rules := metricsRules(Inventory{Connections: []model.Connection{c}}, MetricsSettings{Enabled: true}, map[string]bool{c.ID: true})
		family := "ipv4"
		if c.Bind == "::" {
			family = "ipv6"
		}
		if strings.Count(rules, "meta nfproto "+family) != 4 {
			t.Fatal("wildcard guard can affect another address family", rules)
		}
	}
}

func TestKernelWildcardAccountingKeepsFamilyWithoutPinningAnAddress(t *testing.T) {
	for _, c := range []model.Connection{{ID: "F000003", Engine: "nftables", Enabled: true, Bind: "0.0.0.0", Protocol: "tcp", Ports: "443", Interface: "any"}, {ID: "F000004", Engine: "iptables", Enabled: true, Bind: "::", Protocol: "both", Ports: "8443", Interface: "eth1"}} {
		rules := metricsRules(Inventory{Connections: []model.Connection{c}}, MetricsSettings{Enabled: true}, map[string]bool{c.ID: true})
		family := "ipv4"
		if c.Bind == "::" {
			family = "ipv6"
		}
		if strings.Contains(rules, "daddr "+c.Bind) || strings.Count(rules, "meta nfproto "+family+" ct original proto-dst "+c.Ports) != 4 {
			t.Fatal("wildcard accounting must match every local address of one family", rules)
		}
	}
}
