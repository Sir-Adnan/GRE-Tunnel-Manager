package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/health"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func poolInventory() Inventory {
	return Inventory{Connections: []model.Connection{
		{ID: "F000001", Engine: "nftables", Protocol: "tcp", Ports: "443", Enabled: true, Targets: []model.Target{{IP: "192.0.2.1", Port: 443, Weight: 1}, {IP: "192.0.2.2", Port: 443, Weight: 1}, {IP: "192.0.2.2", Port: 443, Weight: 2}, {IP: "192.0.2.3", Port: 443, Weight: 1}}},
		{ID: "F000002", Engine: "iptables", Protocol: "udp", Ports: "51820", Enabled: true, Targets: []model.Target{{IP: "192.0.2.4", Port: 51820, Weight: 1}, {IP: "192.0.2.5", Port: 51820, Weight: 1}}},
		{ID: "F000003", Engine: "haproxy", Protocol: "tcp", Ports: "8443", Enabled: true, Targets: []model.Target{{IP: "192.0.2.6", Port: 8443, Weight: 1}, {IP: "192.0.2.7", Port: 8443, Weight: 1}}},
		{ID: "F000005", Engine: "nftables", Protocol: "tcp", Ports: "9000", Enabled: true, Targets: []model.Target{{IP: "192.0.2.8", Port: 9000, Weight: 1}}},
	}}
}

func TestHealthTargetsKeepEveryPositionOfADuplicateEndpoint(t *testing.T) {
	for _, target := range healthTargets(poolInventory()) {
		if target.Key == "F000001|tcp|192.0.2.2|443" && (len(target.Indexes) != 2 || target.Indexes[0] != 2 || target.Indexes[1] != 3) {
			t.Fatalf("indexes: %v", target.Indexes)
		}
	}
}

func TestDesiredExclusionsNeverDropEveryDestination(t *testing.T) {
	inventory := poolInventory()
	settings := health.Defaults()
	settings.Enabled, settings.Failover = true, []string{"F000001", "F000002", "F000003"}
	statuses := map[string]string{"F000001|tcp|192.0.2.2|443": health.StatusDown, "F000001|tcp|192.0.2.3|443": health.StatusUnknown, "F000002|icmp|192.0.2.4": health.StatusDown, "F000002|icmp|192.0.2.5": health.StatusDown}
	want := desiredExclusions(settings, inventory, statuses)
	// HAProxy has its own checks and single-destination forwards have nothing to fail over to.
	if len(want) != 2 || want["F000001"] != "2,3" || want["F000002"] != "-" {
		t.Fatalf("want: %v", want)
	}
	settings.Enabled = false
	if got := desiredExclusions(settings, inventory, statuses); got["F000001"] != "-" {
		t.Fatalf("monitoring off: %v", got)
	}
	settings.Enabled, settings.Failover = true, []string{}
	if got := desiredExclusions(settings, inventory, statuses); got["F000001"] != "-" {
		t.Fatalf("not selected: %v", got)
	}
}

func TestFailoverReconcileRunsOnlyOnChangeAndRetriesLater(t *testing.T) {
	inventory := poolInventory()
	connections := connectionsOf(inventory)
	file := filepath.Join(t.TempDir(), "excluded.tsv")
	if e := os.WriteFile(file, []byte("F000002\tx\t1\n"), 0600); e != nil {
		t.Fatal(e)
	}
	calls := []string{}
	fail := false
	exclude := func(_ context.Context, id, list string) (string, error) {
		calls = append(calls, id+" "+list)
		if fail {
			return "", errors.New("busy")
		}
		return "ok", nil
	}
	f := &failover{}
	now := time.Now()
	// F000001 is known clean; F000002 is in the runtime file, so its state is re-sent.
	f.reconcile(context.Background(), now, file, map[string]string{"F000001": "-", "F000002": "-"}, connections, exclude)
	if strings.Join(calls, ";") != "F000002 -" {
		t.Fatalf("first round: %v", calls)
	}
	f.reconcile(context.Background(), now, file, map[string]string{"F000001": "2,3", "F000002": "-"}, connections, exclude)
	f.reconcile(context.Background(), now, file, map[string]string{"F000001": "2,3", "F000002": "-"}, connections, exclude)
	if strings.Join(calls, ";") != "F000002 -;F000001 2,3" || len(f.view()["F000001"].Excluded) != 2 {
		t.Fatalf("change: %v %+v", calls, f.view())
	}
	fail = true
	f.reconcile(context.Background(), now, file, map[string]string{"F000001": "-"}, connections, exclude)
	f.reconcile(context.Background(), now.Add(10*time.Second), file, map[string]string{"F000001": "-"}, connections, exclude)
	if len(calls) != 3 || f.view()["F000001"].Error == "" || len(f.view()["F000001"].Excluded) != 2 {
		t.Fatalf("failure: %v %+v", calls, f.view())
	}
	fail = false
	f.reconcile(context.Background(), now.Add(2*failoverRetry), file, map[string]string{"F000001": "-"}, connections, exclude)
	if len(calls) != 4 || len(f.view()["F000001"].Excluded) != 0 || f.view()["F000001"].Error != "" {
		t.Fatalf("retry: %v %+v", calls, f.view())
	}
	// Editing the destination list re-sends even an unchanged list.
	edited := poolInventory()
	edited.Connections[0].Targets = edited.Connections[0].Targets[:3]
	f.reconcile(context.Background(), now.Add(3*failoverRetry), file, map[string]string{"F000001": "-"}, connectionsOf(edited), exclude)
	if len(calls) != 5 {
		t.Fatalf("edit: %v", calls)
	}
}

func TestHAProxyStatsMapToHealthResults(t *testing.T) {
	stats := "# pxname,svname,qcur,qmax,scur,smax,slim,stot,bin,bout,dreq,dresp,ereq,econ,eresp,wretr,wredis,status,weight,act,bck,chkfail,chkdown,lastchg,downtime,qlimit,pid,iid,sid,throttle,lbtot,tracked,type,rate,rate_lim,rate_max,check_status,check_code,check_duration\n" +
		"front,FRONTEND,,,3,10,2000,40,,,,,,,,,,OPEN,,,,,,,,,1,1,0,,,,0,0,0,5,,,\n" +
		"destinations,target1,0,0,12,20,,100,,,,,,0,0,0,0,UP,1,1,0,0,0,10,0,,1,2,1,,90,,2,0,,4,L4OK,,3\n" +
		"destinations,target2,0,0,0,1,,4,,,,,,1,0,0,0,DOWN,1,0,1,3,1,10,5,,1,2,2,,4,,2,0,,1,L4TOUT,,2001\n" +
		"destinations,target3,0,0,0,0,,0,,,,,,0,0,0,0,no check,1,1,0,0,0,0,0,,1,2,3,,0,,2,0,,0,,,\n" +
		"destinations,BACKEND,0,0,12,20,,104,,,,,,,,,,UP,2,1,1,,0,10,0,,1,2,0,,94,,1,0,,5,,,\n"
	servers, e := parseHAProxyStats(strings.NewReader(stats))
	if e != nil || len(servers) != 3 {
		t.Fatal(servers, e)
	}
	up, ok := servers[1].result()
	if !ok || !up.OK || up.RTT != 3 || *up.Sessions != 12 || up.Via != "haproxy" {
		t.Fatalf("up: %+v", up)
	}
	down, ok := servers[2].result()
	if !ok || down.OK || down.Error != "timeout" || !down.Backup {
		t.Fatalf("down: %+v", down)
	}
	if _, ok := servers[3].result(); ok {
		t.Fatal("a server without checks must fall back to the panel's own probe")
	}
	if _, e := parseHAProxyStats(strings.NewReader("Unknown command\n")); e == nil {
		t.Fatal("garbage accepted")
	}
}

func TestOptimizeParsersAndArguments(t *testing.T) {
	status := "meta\tmemory\t1073741824\nmeta\tflows\t42\nmeta\tcongestion\treno cubic bbr\nmeta\tsteps\t2\nmeta\tfile\t/etc/sysctl.d/zz-gre-manager-optimize.conf\nmeta\tservertools\t/etc/sysctl.d/99-zz-server-tools.conf\n" +
		"key\tconntrack\tnet.netfilter.nf_conntrack_max\t131072\t65536\t131072\tconntrack\t-\t-\t131072\tflow-limit\tsame\n" +
		"key\trelay\tnet.ipv4.tcp_rmem\t4096 87380 6291456\t-\t-\t-\t/etc/sysctl.d/99-zz-server-tools.conf\t4096 131072 33554432\t4096 131072 33554432\tbuffers\tchange\n"
	v, e := parseOptimizeStatus(status)
	if e != nil || v.Memory != 1073741824 || *v.Flows != 42 || len(v.Congestion) != 3 || v.Steps != 2 || len(v.ServerTools) != 1 || len(v.Keys) != 2 {
		t.Fatalf("%+v %v", v, e)
	}
	if v.Keys[0].Note != "same" || v.Keys[1].Recommended != "4096 131072 33554432" || v.Keys[0].Before != "65536" || v.Keys[0].AppliedGroup != "conntrack" || v.Keys[1].OtherValue != "4096 131072 33554432" || v.Keys[1].Applied != "" {
		t.Fatalf("keys: %+v", v.Keys)
	}
	if _, e := parseOptimizeStatus("garbage"); e == nil {
		t.Fatal("garbage accepted")
	}
	plan := parseOptimizePlan([]string{"conntrack"}, OptimizeProfile{}, "change\tconntrack\tnet.netfilter.nf_conntrack_tcp_timeout_established\t432000\t3600\tidle-tcp\tchange\t/etc/sysctl.d/99-zz-server-tools.conf\t7200\n")
	if len(plan.Changes) != 1 || plan.Changes[0].Note != "change" || plan.Changes[0].OtherValue != "7200" {
		t.Fatalf("plan: %+v", plan)
	}
	for _, in := range []OptimizeInput{{}, {Groups: []string{"rm -rf"}}, {Groups: []string{"relay", "relay"}}} {
		if _, e := in.groups(); e == nil {
			t.Errorf("accepted %+v", in)
		}
	}
	if groups, e := (OptimizeInput{Groups: []string{"relay", "conntrack"}}).groups(); e != nil || strings.Join(groups, " ") != "conntrack relay" {
		t.Fatal(groups, e)
	}
}

func TestFlowCountsFromOwnedTableListing(t *testing.T) {
	listing := `{"nftables":[{"metainfo":{}},
{"rule":{"family":"inet","table":"gre_manager","chain":"b_F000001_tcp_0","expr":[{"match":{}},{"counter":{"packets":10,"bytes":600}},{"dnat":{}}]}},
{"rule":{"family":"inet","table":"gre_manager","chain":"b_F000001_udp_0","expr":[{"counter":{"packets":5,"bytes":300}}]}},
{"rule":{"family":"inet","table":"gre_manager","chain":"b_F000001_tcp_1","expr":[{"counter":{"packets":3,"bytes":180}}]}},
{"rule":{"family":"inet","table":"gre_manager","chain":"b_F000009_tcp_0","expr":[{"counter":{"packets":99,"bytes":1}}]}},
{"rule":{"family":"inet","table":"gre_manager","chain":"pre","comment":"gtm-F000001","expr":[{"counter":{"packets":18,"bytes":1}}]}}]}`
	c, e := parseFlowCounts("F000001", 2, []byte(listing))
	if e != nil || c.Total != 18 || c.Destinations[0] != 15 || c.Destinations[1] != 3 {
		t.Fatalf("%+v %v", c, e)
	}
	single, _ := parseFlowCounts("F000001", 1, []byte(`{"nftables":[{"rule":{"chain":"pre","comment":"gtm-F000001","expr":[{"counter":{"packets":7}}]}}]}`))
	if single.Destinations[0] != 7 {
		t.Fatalf("single: %+v", single)
	}
}

func TestDemoShowsFailoverOptimizationAndFlows(t *testing.T) {
	d := NewDemo()
	ctx := context.Background()
	raw, e := d.Do(ctx, Request{Action: "health"})
	if e != nil || !strings.Contains(string(raw), `"F000004":{"excluded":[2]`) {
		t.Fatalf("health: %s %v", raw, e)
	}
	if raw, e = d.Do(ctx, Request{Action: "health-flows", Health: HealthInput{Owner: "F000004"}}); e != nil || !strings.Contains(string(raw), `"destinations":[`) {
		t.Fatalf("flows: %s %v", raw, e)
	}
	if raw, e = d.Do(ctx, Request{Action: "optimize-plan", Optimize: OptimizeInput{Groups: []string{"conntrack"}}}); e != nil || !strings.Contains(string(raw), `"value":"131072"`) {
		t.Fatalf("plan: %s %v", raw, e)
	}
	for _, step := range []Request{{Action: "optimize-apply", Optimize: OptimizeInput{Groups: []string{"conntrack"}}}, {Action: "optimize-apply", Optimize: OptimizeInput{Groups: []string{"relay"}}}, {Action: "optimize-undo"}} {
		if _, e = d.Do(ctx, step); e != nil {
			t.Fatal(step.Action, e)
		}
	}
	raw, _ = d.Do(ctx, Request{Action: "optimize"})
	if !strings.Contains(string(raw), `"steps":1`) || !strings.Contains(string(raw), `"current":"cubic"`) || !strings.Contains(string(raw), `"current":"131072","before":"65536"`) {
		t.Fatalf("after undo: %s", raw)
	}
	if _, e = d.Do(ctx, Request{Action: "optimize-remove", Optimize: OptimizeInput{Group: "all"}}); e != nil {
		t.Fatal(e)
	}
	if raw, _ = d.Do(ctx, Request{Action: "optimize"}); !strings.Contains(string(raw), `"current":"65536"`) || !strings.Contains(string(raw), `"steps":0`) {
		t.Fatalf("after reset: %s", raw)
	}
}
