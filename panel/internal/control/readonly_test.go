package control

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadOnlyBrokerRejectsEveryWriteBeforeExecution(t *testing.T) {
	for _, b := range []*Broker{{ReadOnly: true}, {ReadOnly: true, Nodes: &NodeExecutor{}}} { // A nil manager proves rejected actions never execute.
		for _, action := range []string{"create", "delete", "service", "logs", "doctor", "install", "metrics", "metrics-configure", "metrics-reset", "metrics-policy", "metrics-forget", "resource-rename", "gre-create", "reverse-create", "configuration", "configuration-review", "configuration-apply", "shell", "node-task", "uninstall-prepare"} {
			r := httptest.NewRequest("POST", "http://broker/control", strings.NewReader(`{"action":"`+action+`"}`))
			w := httptest.NewRecorder()
			b.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("%s: %d", action, w.Code)
			}
		}
	}
}

func TestAgentTrafficDoesNotGrantOtherOperations(t *testing.T) {
	b := &Broker{ReadOnly: true, AgentTraffic: true}
	for _, action := range []string{"create", "service", "logs", "install", "metrics-history", "metrics-reset", "metrics-policy", "metrics-forget", "resource-rename", "configuration", "configuration-review", "configuration-apply", "node-task", "shell"} {
		w := httptest.NewRecorder()
		b.ServeHTTP(w, httptest.NewRequest("POST", "/control", strings.NewReader(`{"action":"`+action+`"}`)))
		if w.Code != 403 {
			t.Fatalf("traffic opt-in granted %s: %d", action, w.Code)
		}
	}
}
