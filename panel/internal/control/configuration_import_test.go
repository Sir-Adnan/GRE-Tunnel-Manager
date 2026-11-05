package control

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

const haImportFixture = `global
 log /dev/log local0
 chroot /var/lib/haproxy
 stats socket /run/haproxy/admin.sock mode 660 level admin
 user haproxy
 group haproxy
 daemon
defaults
 mode tcp
 log global
 option tcplog
 option dontlognull
 option redispatch
 option tcpka
 retries 2
 timeout connect 5s
 timeout client 5m
 timeout server 5m
 timeout tunnel 10m
 timeout client-fin 10s
 timeout server-fin 10s
 timeout queue 30s
 default-server inter 3s fall 3 rise 2
frontend frontend_4900
 bind *:4900
 default_backend backend_4900
backend backend_4900
 balance leastconn
 stick-table type ip size 150k expire 1h
 stick on src
 server server_du_1 198.51.100.10:43582 check
 server server_du_2 198.51.100.11:43582 check weight 2
frontend frontend_4901
 bind [::]:4901
 default_backend backend_4901
backend backend_4901
 server single 198.51.100.12:43582
`

func TestHAImportPreservesTCPPolicyAndReportsProcessChanges(t *testing.T) {
	cs, w, e := parseImport(ImportInput{Engine: "haproxy", Format: "haproxy", Text: haImportFixture})
	if e != nil {
		t.Fatal(e)
	}
	if len(cs) != 2 || len(w) != 7 {
		t.Fatal(cs, w)
	}
	c := cs[0]
	if c.Ports != "4900" || c.Bind != "0.0.0.0" || c.Enabled || c.Strategy != "leastconn" || len(c.Targets) != 2 || c.Targets[1].Weight != 2 {
		t.Fatal(c)
	}
	for key, value := range map[string]string{"idle": "300", "tunnel": "600", "fin": "10", "stick": "source", "stick_size": "150000", "stick_expire": "3600", "maxconn": "0", "check_interval": "3", "log": "connections"} {
		if c.Options[key] != value {
			t.Fatalf("%s: %v", key, c.Options)
		}
	}
	if cs[1].Options["check_mode"] != "off" || cs[1].Bind != "::" {
		t.Fatal(cs[1])
	}
}
func TestImportRejectsUnknownLossyAndExecutableStructures(t *testing.T) {
	for _, text := range []string{
		haImportFixture + "\nprogram dangerous\n command /bin/sh\n",
		strings.Replace(haImportFixture, "timeout server 5m", "timeout server 6m", 1),
		strings.Replace(haImportFixture, "check weight 2", "check weight 2 send-proxy-v2", 1),
		strings.Replace(haImportFixture, "default_backend backend_4900", "use_backend backend_4900 if true", 1),
		haImportFixture + "\nbackend unused\n server x 198.51.100.99:443\n",
		strings.Replace(haImportFixture, "43582 check", "43582 check init-addr libc,none", 1),
		strings.Replace(haImportFixture, "size 150k", "size 2000k", 1),
	} {
		if _, _, e := parseImport(ImportInput{Engine: "haproxy", Format: "haproxy", Text: text}); e == nil {
			t.Fatal("unsafe or lossy import accepted", text)
		}
	}
}
func TestRealmImportSupportsMultipleSimpleEndpointsAndClosedNetworkOptions(t *testing.T) {
	text := "[log]\nlevel = \"off\"\n[network]\nuse_udp = true\ntcp_timeout = 8\nudp_timeout = 120\n[[endpoints]]\nlisten = \"0.0.0.0:4000\"\nremote = \"198.51.100.20:443\"\n[[endpoints]]\nlisten = \"[::]:4001\"\nremote = \"[2001:db8::20]:8443\"\n"
	cs, _, e := parseImport(ImportInput{Engine: "realm", Format: "realm", Text: text})
	if e != nil {
		t.Fatal(e)
	}
	if len(cs) != 2 || cs[1].Protocol != "both" || cs[1].Options["udp_timeout"] != "120" {
		t.Fatal(cs)
	}
	for _, suffix := range []string{"\nexec = \"sh\"", "\n[network]\nuse_udp = false"} {
		if _, _, e := parseImport(ImportInput{Engine: "realm", Format: "realm", Text: text + suffix}); e == nil {
			t.Fatal("unknown or late global accepted")
		}
	}
}
func TestImportReviewIsReadOnlyAndApplyRejectsChangedGeneration(t *testing.T) {
	d := NewDemo()
	base := len(d.inventory.Connections)
	ctx := context.Background()
	in := ImportInput{Engine: "haproxy", Format: "haproxy", Text: haImportFixture}
	b, e := d.Do(ctx, Request{Action: "configuration-import-review", Import: in})
	if e != nil {
		t.Fatal(e)
	}
	var view ImportView
	json.Unmarshal(b, &view)
	if len(d.inventory.Connections) != base || len(view.Files) != 2 {
		t.Fatal("review changed state or omitted output")
	}
	in.Review = view.Review
	in.Text += "\n# changed\n"
	if _, e = d.Do(ctx, Request{Action: "configuration-import-apply", Import: in}); e == nil {
		t.Fatal("changed input accepted")
	}
	in.Text = haImportFixture
	if _, e = d.Do(ctx, Request{Action: "configuration-import-apply", Import: in}); e != nil {
		t.Fatal(e)
	}
	if len(d.inventory.Connections) != base+2 || d.inventory.Connections[base].Enabled {
		t.Fatal("import not paused")
	}
	if _, e = d.Do(ctx, Request{Action: "configuration-import-apply", Import: in}); e == nil {
		t.Fatal("replayed import accepted")
	}
}
func TestManagedJSONImportForBothFirewalls(t *testing.T) {
	for _, engine := range []string{"iptables", "nftables"} {
		c := model.Connection{Name: "Imported forward", Engine: engine, Protocol: "both", Bind: "192.0.2.10", Ports: "5000", Strategy: "single", SNAT: "masquerade", Interface: "any", Targets: []model.Target{{IP: "198.51.100.20", Port: 443, Weight: 1}}}
		b, _ := json.Marshal([]model.Connection{c})
		cs, _, e := parseImport(ImportInput{Engine: engine, Format: "json", Text: string(b), Activate: true})
		if e != nil || !cs[0].Enabled {
			t.Fatal(engine, e)
		}
		if e = importConflicts(cs, cs); e == nil {
			t.Fatal("duplicate entrance accepted")
		}
	}
}
