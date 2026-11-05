package health

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestFailoverSettingsNormalizeAndValidate(t *testing.T) {
	s := Defaults()
	if s.FailoverInterval != 5 || s.Failover == nil {
		t.Fatalf("defaults: %+v", s)
	}
	// Files from v1.3.7 lack both fields and must still load.
	path := filepath.Join(t.TempDir(), "health.json")
	old := `{"settings":{"enabled":true,"interval":30,"fail_threshold":3,"recover_threshold":2,"latency_warn_ms":300,"retention_days":30},"revision":4}`
	if e := os.WriteFile(path, []byte(old), 0600); e != nil {
		t.Fatal(e)
	}
	m, e := Open(path)
	if e != nil {
		t.Fatal(e)
	}
	if got := m.Settings(); got.FailoverInterval != 5 || len(got.Failover) != 0 {
		t.Fatalf("old file: %+v", got)
	}
	for _, bad := range []func(*Settings){
		func(s *Settings) { s.FailoverInterval = 1 },
		func(s *Settings) { s.FailoverInterval = 31 },
		func(s *Settings) { s.Failover = []string{"F000001", "F000001"} },
		func(s *Settings) { s.Failover = []string{"gre-tun-1"} },
	} {
		s := Defaults()
		bad(&s)
		if s.Validate() == nil {
			t.Errorf("accepted %+v", s)
		}
	}
	s.Failover = []string{"F000001", "F000004"}
	if e := s.Validate(); e != nil || !s.FailoverSet()["F000004"] {
		t.Fatal(e)
	}
}

func TestLossAndCheckerFieldsInView(t *testing.T) {
	m := New()
	s := Defaults()
	s.Enabled = true
	if e := m.Configure(time.Now(), s, 0); e != nil {
		t.Fatal(e)
	}
	ping := Target{Key: "gre|icmp", Owner: "gre-tun-1", Kind: KindICMP, Address: "10.0.1.2"}
	relay := Target{Key: "F1|tcp", Owner: "F000001", Engine: "haproxy", Kind: KindTCP, Address: "192.0.2.1", Port: 443}
	now := time.Now().UTC()
	sessions := 7
	for i := 0; i < 4; i++ {
		at := now.Add(time.Duration(i) * time.Second)
		results := map[string]Result{ping.Key: {OK: i != 1, RTT: 20}, relay.Key: {OK: true, RTT: 2, Via: "haproxy", Sessions: &sessions, Backup: true}}
		m.Record(at, []Target{ping, relay}, results, nil)
	}
	v := m.View(now.Add(5*time.Second), time.UTC)
	for _, o := range v.Owners {
		for _, target := range o.Targets {
			switch target.Key {
			case ping.Key:
				if target.Loss24h == nil || *target.Loss24h != 25 {
					t.Fatalf("loss: %v", target.Loss24h)
				}
			case relay.Key:
				if target.Via != "haproxy" || target.Sessions == nil || *target.Sessions != 7 || !target.Backup {
					data, _ := json.Marshal(target)
					t.Fatalf("checker fields: %s", data)
				}
			}
		}
	}
	if m.Statuses()[ping.Key] != StatusUp {
		t.Fatal("one lost ping must not mark the link down")
	}
}

type fakeEcho struct {
	limit int
	sent  []int
}

func (f *fakeEcho) Echo(_ context.Context, size int) (bool, error) {
	f.sent = append(f.sent, size)
	return size <= f.limit, nil
}
func (f *fakeEcho) Close() error { return nil }

func TestPathMTUSearchIsBounded(t *testing.T) {
	peer := netip.MustParseAddr("10.0.7.1")
	for _, c := range []struct{ limit, link, want int }{{1476, 1476, 1476}, {1436, 1476, 1436}, {1200, 1476, 1200}, {1000, 1476, 0}} {
		f := &fakeEcho{limit: c.limit}
		r, e := searchMTU(context.Background(), f, peer, c.link)
		if e != nil || r.Path != c.want || r.Probes > mtuProbes || r.Probes != len(f.sent) {
			t.Errorf("limit %d: got %+v (%v), sent %v", c.limit, r, e, f.sent)
		}
	}
	if _, e := PathMTU(context.Background(), netip.MustParseAddr("2001:db8::1"), 1476); e == nil {
		t.Fatal("IPv6 accepted")
	}
}
