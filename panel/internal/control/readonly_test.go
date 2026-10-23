package control

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestReadOnlyBrokerRejectsEveryWriteBeforeExecution(t *testing.T) {
	for _, b := range []*Broker{{ReadOnly: true}, {ReadOnly: true, Nodes: &NodeExecutor{}}} { // A nil manager proves rejected actions never execute.
		for _, action := range []string{"create", "delete", "service", "logs", "doctor", "install", "metrics", "metrics-configure", "metrics-reset", "metrics-policy", "metrics-forget", "resource-rename", "gre-create", "reverse-create", "shell", "node-task", "uninstall-prepare"} {
			r := httptest.NewRequest("POST", "http://broker/control", strings.NewReader(`{"action":"`+action+`"}`))
			w := httptest.NewRecorder()
			b.ServeHTTP(w, r)
			if w.Code != 403 {
				t.Fatalf("%s: %d", action, w.Code)
			}
		}
	}
}
