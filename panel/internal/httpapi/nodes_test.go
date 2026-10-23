package httpapi

import (
	"encoding/json"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/nodes"
)

func TestNodesLocalOptionalAndProtectedEnrollment(t *testing.T) {
	s := testServer(t)
	if w := request(s, "/api/nodes", "", "", "", nil); w.Code != 401 {
		t.Fatal("anonymous nodes")
	}
	w := request(s, "/api/login", `{"username":"admin","password":"test-panel-password"}`, "http://panel.local", "", nil)
	cookie := w.Result().Cookies()[0]
	var login struct {
		Session auth.Session `json:"session"`
	}
	json.Unmarshal(w.Body.Bytes(), &login)
	w = request(s, "/api/nodes", "", "", "", cookie)
	var listing nodes.Listing
	if json.Unmarshal(w.Body.Bytes(), &listing) != nil || listing.Enabled || len(listing.Nodes) != 1 || !listing.Nodes[0].Local || listing.Nodes[0].Status != "online" {
		t.Fatal(w.Body.String())
	}
	dir := t.TempDir()
	if e := nodes.Init(dir, "https://127.0.0.1:9443", "127.0.0.1:9443"); e != nil {
		t.Fatal(e)
	}
	h, e := nodes.Open(dir)
	if e != nil {
		t.Fatal(e)
	}
	defer h.Close()
	s.Nodes = h
	for _, path := range []string{"/api/nodes/pairs", "/api/nodes/pairs/decision"} {
		if w = request(s, path, `{}`, "http://panel.local", "", cookie); w.Code != 403 {
			t.Fatal("pair write without CSRF accepted")
		}
		if w = request(s, path, `{}`, "http://evil.local", login.Session.CSRF, cookie); w.Code != 403 {
			t.Fatal("foreign pair write accepted")
		}
	}
	if w = request(s, "/api/nodes/pairs", "", "", "", cookie); w.Code != 200 || w.Body.String() != "[]\n" {
		t.Fatal("unexpected initial pair list", w.Body.String())
	}
	if w = request(s, "/api/nodes/invitations", `{"name":"Test"}`, "http://panel.local", "", cookie); w.Code != 403 {
		t.Fatal("missing CSRF accepted")
	}
	if w = request(s, "/api/nodes/invitations", `{"name":"Test"}`, "http://evil.local", login.Session.CSRF, cookie); w.Code != 403 {
		t.Fatal("foreign Origin accepted")
	}
	w = request(s, "/api/nodes/invitations", `{"name":"Test"}`, "http://panel.local", login.Session.CSRF, cookie)
	var invite nodes.Invitation
	if w.Code != 201 || json.Unmarshal(w.Body.Bytes(), &invite) != nil || invite.Code == "" {
		t.Fatal(w.Code, w.Body.String())
	}
	w = request(s, "/api/nodes", "", "", "", cookie)
	if w.Code != 200 {
		t.Fatal(w.Code)
	}
	if string(w.Body.Bytes()) == invite.Code {
		t.Fatal("code redisclosed")
	}
	if w = request(s, "/api/operations", `{"action":"create","node_id":"other"}`, "http://panel.local", login.Session.CSRF, cookie); w.Code != 400 {
		t.Fatal("remote operation field accepted")
	}
}
