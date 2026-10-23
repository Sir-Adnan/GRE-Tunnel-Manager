package control

import (
	"os"
	"path/filepath"
	"testing"
)

func TestRetirementKeepsUnresolvedReceiptsAndRespectsBrokerLock(t *testing.T) {
	x, _, now := newNodeExecutor(t)
	task := nodeTestTask(*now)
	prepare := executeNode(t, x, task)
	if e := x.CheckRetirement(); e != nil {
		t.Fatal(e)
	}
	task.Stage, task.Revision = "apply", prepare.Revision
	executeNode(t, x, task)
	if x.CheckRetirement() == nil {
		t.Fatal("leased resource forgotten")
	}
	task.Stage = "confirm"
	executeNode(t, x, task)
	if e := x.CheckRetirement(); e != nil {
		t.Fatal(e)
	}
	lease, e := nodeLease(filepath.Join(x.Directory, "broker.lock"))
	if e != nil {
		t.Fatal(e)
	}
	if x.CheckRetirement() == nil {
		t.Fatal("live broker accepted")
	}
	lease.Close()
	if e := os.WriteFile(filepath.Join(x.Directory, task.ID+".json"), []byte("broken"), 0600); e != nil {
		t.Fatal(e)
	}
	if x.CheckRetirement() == nil {
		t.Fatal("broken receipt forgotten")
	}
}
