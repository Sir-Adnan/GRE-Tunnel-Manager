package httpapi

import (
	"bytes"
	"encoding/json"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"net/http/httptest"
	"testing"
)

func TestBackupRoutesRequireAuthenticationCSRFAndClosedInput(t *testing.T) {
	s := testServer(t)
	body := `{"password":"backup-password","include_traffic":true}`
	if w := request(s, "/api/backups/export", body, "http://panel.local", "", nil); w.Code != 401 {
		t.Fatal(w.Code)
	}
	w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, "http://panel.local", "", nil)
	cookie := w.Result().Cookies()[0]
	var login struct {
		Session auth.Session `json:"session"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	for _, path := range []string{"export", "review", "restore"} {
		if w = request(s, "/api/backups/"+path, body, "http://panel.local", "", cookie); w.Code != 403 {
			t.Fatal("missing csrf", path, w.Code)
		}
	}
	if w = request(s, "/api/backups/export", body, "http://evil.local", login.Session.CSRF, cookie); w.Code != 403 {
		t.Fatal("foreign origin")
	}
	if w = request(s, "/api/backups/export", `{"path":"/etc/shadow"}`, "http://panel.local", login.Session.CSRF, cookie); w.Code != 400 {
		t.Fatal("path accepted")
	}
	w = request(s, "/api/backups/export", body, "http://panel.local", login.Session.CSRF, cookie)
	var file control.BackupDownload
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &file) != nil || file.Archive == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("backup cached")
	}
	if allowed("backup-restore") {
		t.Fatal("large recovery payload exposed through generic operations")
	}
}
func TestPrivateRecoveryEndpointAndAgentIsolation(t *testing.T) {
	for _, c := range []struct {
		path, action string
		readonly     bool
		status       int
	}{{"/control", "backup-export", false, 400}, {"/backup", "inventory", false, 400}, {"/backup", "backup-export", true, 403}} {
		b := control.Broker{ReadOnly: c.readonly}
		body, _ := json.Marshal(control.Request{Action: c.action, Backup: control.BackupInput{Password: "test-backup-password"}})
		r := httptest.NewRequest("POST", c.path, bytes.NewReader(body))
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		if w.Code != c.status {
			t.Fatal(c, w.Code, w.Body.String())
		}
	}
}
