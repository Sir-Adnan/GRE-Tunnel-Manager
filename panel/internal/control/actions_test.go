package control

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestActionRegistryClassesAreDisjoint(t *testing.T) {
	for name, spec := range actions {
		classes := 0
		for _, set := range []bool{spec.read, spec.public, spec.backup} {
			if set {
				classes++
			}
		}
		if classes > 1 {
			t.Fatal("action has more than one class:", name)
		}
	}
	// Mutations must stay audited and serialized; backups never use /control.
	for _, name := range []string{"create", "delete", "install", "configuration-apply", "node-task"} {
		if ReadAction(name) {
			t.Fatal("mutation classified as read:", name)
		}
	}
	if PublicOperation("backup-restore") || PublicOperation("node-task") || PublicOperation("inventory") || PublicOperation("unknown") {
		t.Fatal("public operation allowlist widened")
	}
}

func TestBrokerReadsDoNotWaitForAMutation(t *testing.T) {
	b := &Broker{Manager: &Manager{}}
	b.mu.Lock() // A long apply or package installation holds the mutation lock.
	defer b.mu.Unlock()
	w := httptest.NewRecorder()
	done := make(chan struct{})
	go func() {
		b.ServeHTTP(w, httptest.NewRequest("POST", "/control", strings.NewReader(`{"action":"capabilities"}`)))
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("read queued behind the mutation lock")
	}
	if !strings.Contains(w.Body.String(), `"data"`) {
		t.Fatal(w.Body.String())
	}
}
