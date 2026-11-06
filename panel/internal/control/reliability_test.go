package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recoveryFailureRunner struct{ calls int }

func (r *recoveryFailureRunner) Run(_ context.Context, _ string, args []string, _ string) (string, error) {
	if len(args) > 2 && args[2] == "recovery-revision" {
		return strings.Repeat("b", 64), nil
	}
	r.calls++
	return "", errors.New("simulated lock contention")
}

func TestSafeApplyRetainsFailedRecoveryAndBoundsAutomaticRetries(t *testing.T) {
	dir := t.TempDir()
	o, e := NewOperations(dir)
	if e != nil {
		t.Fatal(e)
	}
	r := &recoveryFailureRunner{}
	m := &Manager{Runner: r, Ops: o}
	now := time.Now().UTC()
	if e = m.armSafe(context.Background(), Request{Action: "update", SafeMinutes: 2}, now.Add(-3*time.Minute), "receipt\t20261106T120000-1-1.tsv\t"+strings.Repeat("b", 64)); e != nil {
		t.Fatal(e)
	}
	for i := 1; i <= 3; i++ {
		m.checkSafe(context.Background(), now.Add(time.Duration(i)*2*time.Minute))
		pending := o.pendingSafe()
		if pending == nil || pending.Attempts != i || pending.LastError == "" {
			t.Fatal(pending)
		}
	}
	m.checkSafe(context.Background(), now.Add(time.Hour))
	if r.calls != 3 {
		t.Fatal("unbounded automatic retries", r.calls)
	}
	again, e := NewOperations(dir)
	if e != nil || again.pendingSafe() == nil || again.pendingSafe().Attempts != 3 {
		t.Fatal(again, e)
	}
	if e = CheckPanelRetirement(dir); e == nil {
		t.Fatal("removal discarded pending recovery")
	}
	if _, e = m.safeChange(context.Background(), Request{Action: "change-confirm"}); e != nil {
		t.Fatal(e)
	}
	if e = CheckPanelRetirement(dir); e != nil {
		t.Fatal(e)
	}
}

func TestSafeApplyUsesExactReceiptAndRejectsAnOldHelper(t *testing.T) {
	o, e := NewOperations(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	m := &Manager{Ops: o}
	if e = m.armSafe(context.Background(), Request{}, time.Now(), "Saved and applied. Restore point: 20261106T120000-1-1.tsv"); e == nil {
		t.Fatal("missing exact revision accepted")
	}
	if o.pendingSafe() != nil {
		t.Fatal("armed without receipt")
	}
}

func TestPanelRetirementChecksActiveWatchesAndUnsafeFiles(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "optimize-watch.json")
	if e := os.WriteFile(path, []byte(`{"started":"2026-11-06T12:00:00Z","result":"active"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if CheckPanelRetirement(dir) == nil {
		t.Fatal("active watch accepted")
	}
	if e := os.WriteFile(path, []byte(`{"started":"2026-11-06T12:00:00Z","result":"kept"}`), 0600); e != nil {
		t.Fatal(e)
	}
	if e := CheckPanelRetirement(dir); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(filepath.Join(dir, "safe-change.json"), []byte(`{}`), 0600); e != nil {
		t.Fatal(e)
	}
	if CheckPanelRetirement(dir) == nil {
		t.Fatal("invalid recovery accepted")
	}
}

type resolvedFlowRunner struct{ script *scriptRunner }

func (r resolvedFlowRunner) Run(ctx context.Context, name string, args []string, input string) (string, error) {
	if name == "nft" {
		return `{"nftables":[{"rule":{"chain":"pre","comment":"gtm-F000003","expr":[{"counter":{"packets":10}}]}},{"rule":{"chain":"b_F000003_tcp_0","expr":[{"counter":{"packets":3}}]}},{"rule":{"chain":"b_F000003_tcp_1","expr":[{"counter":{"packets":7}}]}}]}`, nil
	}
	return r.script.Run(ctx, name, args, input)
}

func TestFlowDistributionUsesEveryResolvedBackend(t *testing.T) {
	r := resolvedFlowRunner{script: &scriptRunner{answers: map[string]string{
		"state":     domainRow() + "\n",
		"dns-cache": "record\tF000003\t203.0.113.10:443@1,203.0.113.11:443@1\n",
	}}}
	m := &Manager{Runner: r}
	c, e := m.flowCounts(context.Background(), "F000003")
	if e != nil || len(c.Destinations) != 2 || c.Destinations[0] != 3 || c.Destinations[1] != 7 || c.Total != 10 {
		t.Fatal(c, e)
	}
}
