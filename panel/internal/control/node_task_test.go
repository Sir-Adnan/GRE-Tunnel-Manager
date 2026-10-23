package control

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type pairRunner struct {
	calls                          []string
	revision, fingerprint          string
	changed, failApply, failDelete bool
	preflightChanged               bool
}

func (r *pairRunner) Run(_ context.Context, _ string, args []string, _ string) (string, error) {
	action := args[2]
	r.calls = append(r.calls, action)
	switch action {
	case "pair-check-gre", "pair-check-frp":
		return "native check passed\n" + r.revision + "\n", nil
	case "pair-apply-gre", "pair-apply-frp":
		if r.preflightChanged {
			return "", preflightChangedError{}
		}
		if r.failApply {
			return "partial startup", errors.New("failed")
		}
		return "created\n" + r.fingerprint + "\n", nil
	case "pair-verify":
		if r.changed {
			return "", errors.New("changed")
		}
		return "", nil
	case "pair-delete":
		if r.changed || r.failDelete {
			return "", errors.New("refused")
		}
		return "", nil
	}
	return "", errors.New("unexpected command")
}

type preflightChangedError struct{}

func (preflightChangedError) Error() string { return "preflight changed" }
func (preflightChangedError) ExitCode() int { return 75 }
func newNodeExecutor(t *testing.T) (*NodeExecutor, *pairRunner, *time.Time) {
	t.Helper()
	now := time.Now()
	r := &pairRunner{revision: strings.Repeat("a", 64), fingerprint: strings.Repeat("b", 64)}
	return &NodeExecutor{Manager: &Manager{Runner: r}, Directory: t.TempDir(), Now: func() time.Time { return now }}, r, &now
}
func nodeTestTask(now time.Time) NodeTask {
	return NodeTask{ID: strings.Repeat("a", 32), Stage: "prepare", Expires: now.Add(10 * time.Minute), Spec: NodeSpec{Kind: "gre", GRE: GRE{ID: 1, Role: "iran", Remote: "198.51.100.2", Bind: "192.0.2.1", MTU: 1430}}}
}
func executeNode(t *testing.T, x *NodeExecutor, task NodeTask) NodeResult {
	t.Helper()
	out, e := x.Execute(context.Background(), task)
	if e != nil {
		t.Fatal(e)
	}
	return out
}
func TestNodeTaskIdempotencyRevisionAndLease(t *testing.T) {
	x, r, now := newNodeExecutor(t)
	task := nodeTestTask(*now)
	p := executeNode(t, x, task)
	if p.State != "prepared" || p.Revision != r.revision {
		t.Fatal(p)
	}
	executeNode(t, x, task)
	if len(r.calls) != 1 {
		t.Fatal("prepare replayed")
	}
	task.Stage = "apply"
	task.Revision = "wrong"
	if executeNode(t, x, task).Code != "revision_conflict" {
		t.Fatal("stale accepted")
	}
	task.Revision = p.Revision
	a := executeNode(t, x, task)
	if a.State != "applied" || a.Deadline == nil {
		t.Fatal(a)
	}
	executeNode(t, x, task)
	if len(r.calls) != 2 {
		t.Fatal("create replayed")
	}
	*now = now.Add(6 * time.Minute)
	restarted := &NodeExecutor{Manager: x.Manager, Directory: x.Directory, Now: x.Now}
	if e := restarted.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	task.Stage = "status"
	if out := executeNode(t, x, task); out.State != "rolled_back" {
		t.Fatal(out)
	}
	if strings.Join(r.calls, ",") != "pair-check-gre,pair-apply-gre,pair-delete" {
		t.Fatal(r.calls)
	}
}
func TestNodeTaskConfirmRestartAndChangedResource(t *testing.T) {
	x, r, now := newNodeExecutor(t)
	task := nodeTestTask(*now)
	p := executeNode(t, x, task)
	task.Stage = "apply"
	task.Revision = p.Revision
	executeNode(t, x, task)
	restarted := &NodeExecutor{Manager: x.Manager, Directory: x.Directory, Now: x.Now}
	r.changed = true
	task.Stage = "confirm"
	if executeNode(t, restarted, task).Code != "resource_changed" {
		t.Fatal("changed resource confirmed")
	}
	task.Stage = "rollback"
	out := executeNode(t, restarted, task)
	if out.State != "unknown" || out.Code != "rollback_needs_inspection" {
		t.Fatal(out)
	}
	// Repeated rollback of an uncertain resource must not attempt deletion again.
	calls := len(r.calls)
	executeNode(t, restarted, task)
	if len(r.calls) != calls {
		t.Fatal("unsafe retry")
	}
}
func TestNodeTaskCommittedSurvivesLeaseAndInterruptedCreateDoesNotReplay(t *testing.T) {
	x, r, now := newNodeExecutor(t)
	task := nodeTestTask(*now)
	p := executeNode(t, x, task)
	task.Stage = "apply"
	task.Revision = p.Revision
	executeNode(t, x, task)
	task.Stage = "confirm"
	if executeNode(t, x, task).State != "committed" {
		t.Fatal("confirm failed")
	}
	*now = now.Add(6 * time.Minute)
	if e := x.Recover(context.Background()); e != nil {
		t.Fatal(e)
	}
	if len(r.calls) != 3 {
		t.Fatal("committed resource removed")
	}
	receipt, e := x.load(task.ID)
	if e != nil {
		t.Fatal(e)
	}
	receipt.Result.State = "executing"
	if e = x.save(receipt); e != nil {
		t.Fatal(e)
	}
	task.Stage = "apply"
	if executeNode(t, x, task).Code != "interrupted" {
		t.Fatal("missing uncertain outcome")
	}
	if len(r.calls) != 3 {
		t.Fatal("interrupted create replayed")
	}
}
func TestNodeTaskFailsClosed(t *testing.T) {
	x, r, now := newNodeExecutor(t)
	task := nodeTestTask(*now)
	invalid := task
	invalid.ID = "../../escape"
	if executeNode(t, x, invalid).State != "failed" {
		t.Fatal("unsafe ID")
	}
	invalid = task
	invalid.Expires = *now
	if executeNode(t, x, invalid).Code != "expired" {
		t.Fatal("expired request accepted")
	}
	executeNode(t, x, task)
	invalid = task
	invalid.Spec.GRE.ID = 2
	if executeNode(t, x, invalid).Code != "idempotency_conflict" {
		t.Fatal("ID reuse accepted")
	}
	*now = now.Add(11 * time.Minute)
	task.Stage = "apply"
	task.Expires = now.Add(time.Minute)
	task.Revision = r.revision
	if executeNode(t, x, task).Code != "expired" {
		t.Fatal("old preparation extended")
	}
	if len(r.calls) != 1 {
		t.Fatal(r.calls)
	}
	// A corrupt journal must never be interpreted as a new operation.
	if e := os.WriteFile(filepath.Join(x.Directory, task.ID+".json"), []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := x.Execute(context.Background(), task); e == nil {
		t.Fatal("corrupt receipt ignored")
	}
}
func TestNodeTaskFailedApplyRecordedWithoutRawOutput(t *testing.T) {
	x, r, now := newNodeExecutor(t)
	task := nodeTestTask(*now)
	p := executeNode(t, x, task)
	r.failApply = true
	task.Stage = "apply"
	task.Revision = p.Revision
	out := executeNode(t, x, task)
	if out.State != "unknown" {
		t.Fatal(out)
	}
	b, _ := json.Marshal(out)
	if strings.Contains(string(b), "partial startup") {
		t.Fatal("command output leaked")
	}
}

func TestNodeTaskCannotRemoveOldCommittedResource(t *testing.T) {
	x, r, now := newNodeExecutor(t)
	task := nodeTestTask(*now)
	p := executeNode(t, x, task)
	task.Stage = "apply"
	task.Revision = p.Revision
	executeNode(t, x, task)
	task.Stage = "confirm"
	executeNode(t, x, task)
	*now = now.Add(11 * time.Minute)
	task.Stage = "rollback"
	task.Expires = now.Add(time.Minute)
	if executeNode(t, x, task).Code != "committed_resource" {
		t.Fatal("old confirmed resource removed remotely")
	}
	if len(r.calls) != 3 {
		t.Fatal(r.calls)
	}
}
func TestNodeTaskPreflightChangedIsKnownFailure(t *testing.T) {
	x, r, now := newNodeExecutor(t)
	task := nodeTestTask(*now)
	p := executeNode(t, x, task)
	r.preflightChanged = true
	task.Stage = "apply"
	task.Revision = p.Revision
	out := executeNode(t, x, task)
	if out.State != "failed" || out.Code != "preflight_changed" {
		t.Fatal(out)
	}
	task.Stage = "rollback"
	if executeNode(t, x, task).State != "rolled_back" {
		t.Fatal("known no-effect failure did not recover")
	}
	if len(r.calls) != 2 {
		t.Fatal("failed preflight invoked resource deletion")
	}
}
