package control

import (
	"path/filepath"
	"testing"
)

func TestNodeJournalHasSingleBrokerLease(t *testing.T) {
	path := filepath.Join(t.TempDir(), "broker.lock")
	first, e := nodeLease(path)
	if e != nil {
		t.Fatal(e)
	}
	if duplicate, e := nodeLease(path); e == nil {
		duplicate.Close()
		first.Close()
		t.Fatal("two brokers acquired the operation journal")
	}
	if e = first.Close(); e != nil {
		t.Fatal(e)
	}
	next, e := nodeLease(path)
	if e != nil {
		t.Fatal("lease survived process ownership", e)
	}
	next.Close()
}
