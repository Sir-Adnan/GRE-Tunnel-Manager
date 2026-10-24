//go:build linux

package control

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type recoveryTestRunner struct{ config, units, run string }

func (r recoveryTestRunner) Run(ctx context.Context, name string, args []string, input string) (string, error) {
	if name != "/bin/bash" {
		return "", nil
	}
	if len(args) < 3 {
		return "", fmt.Errorf("invalid fixture call")
	}
	script, _ := filepath.Abs("../../../gre.sh")
	cmd := exec.CommandContext(ctx, "bash", "-c", `source "$1"; gtm_paths; gtm_root() { :; }; systemctl() { [[ $1 != is-active ]]; }; gtm_api "${@:2}"`, "recovery-test", script)
	cmd.Args = append(cmd.Args, args[2:]...)
	cmd.Env = append(os.Environ(), "GTM_CONFIG_DIR="+r.config, "GTM_SERVICE_DIR="+r.units, "GTM_RUN_DIR="+r.run, "GTM_SERVER_LOOKUP=0")
	cmd.Stdin = strings.NewReader(input)
	data, e := cmd.CombinedOutput()
	return string(data), e
}
func recoveryManager(t *testing.T) *Manager {
	t.Helper()
	root := t.TempDir()
	r := recoveryTestRunner{filepath.Join(root, "config"), filepath.Join(root, "units"), filepath.Join(root, "run")}
	for _, p := range []string{r.config, r.units, r.run} {
		if e := os.Mkdir(p, 0700); e != nil {
			t.Fatal(e)
		}
	}
	metrics, e := NewMetrics(r, filepath.Join(root, "metrics.json"))
	if e != nil {
		t.Fatal(e)
	}
	return &Manager{Runner: r, ConfigDir: r.config, UnitDir: r.units, Metrics: metrics}
}
func TestReverseRecoveryDecodersRoundTripRealBash(t *testing.T) {
	m := recoveryManager(t)
	for _, engine := range []string{"frp", "rathole"} {
		for _, role := range []string{"entrance", "destination"} {
			for _, transport := range []string{"tcp", "websocket", "quic", "wss"} {
				if engine == "rathole" && transport != "tcp" {
					continue
				}
				t.Run(engine+"-"+role+"-"+transport, func(t *testing.T) {
					r := Reverse{Engine: engine, Name: "vpn", Role: role, Host: "192.0.2.10", Control: 2333, Public: 443, LocalIP: "127.0.0.1", LocalPort: 8443, Protocol: "tcp", Transport: transport, Mux: true, Token: strings.Repeat("T", 24), Group: "vpn", Key: strings.Repeat("A", 43) + "="}
					if engine == "rathole" {
						r.Protocol = "both"
					}
					if transport == "wss" {
						r.Certificate = "/etc/operator/vpn.pem"
						r.Internal = 7001
					}
					input, e := r.Input()
					if e != nil {
						t.Fatal(e)
					}
					raw, e := m.call(context.Background(), "recovery-render", input, engine)
					if e != nil {
						t.Fatal(e, raw)
					}
					gateway := "frontend wss_entrance\n    bind 192.0.2.10:2333 ssl crt /etc/operator/vpn.pem\n"
					restored, e := recoveryReverse("gtm-"+engine+"-"+role+"-vpn", raw, gateway)
					if e != nil {
						t.Fatal(e)
					}
					input, e = restored.Input()
					if e != nil {
						t.Fatal(e)
					}
					again, e := m.call(context.Background(), "recovery-render", input, engine)
					if e != nil || raw != again {
						t.Fatal("nonportable reverse configuration", e, raw, again)
					}
					if restored.Key != r.Key && engine == "rathole" {
						t.Fatal("Noise identity changed")
					}
				})
			}
		}
	}
}
func TestManagerBackupMigratesToFreshInstallationPaused(t *testing.T) {
	ctx := context.Background()
	source := recoveryManager(t)
	doc := backupFixture(t)
	doc.Connections[0].Enabled = false
	r := Reverse{Engine: "rathole", Name: "vpn", Role: "entrance", Host: "192.0.2.10", Control: 2333, Public: 443, LocalIP: "127.0.0.1", LocalPort: 443, Protocol: "both", Transport: "tcp", Token: strings.Repeat("T", 24), Key: strings.Repeat("A", 43) + "="}
	doc.Resources = append(doc.Resources, BackupResource{Name: "Customer reverse", Reverse: &r})
	web := Reverse{Engine: "frp", Name: "webvpn", Role: "entrance", Host: "192.0.2.10", Control: 2443, Public: 5443, LocalIP: "127.0.0.1", LocalPort: 5443, Protocol: "tcp", Transport: "wss", Mux: true, Token: strings.Repeat("T", 24), Group: "webvpn", Certificate: "/etc/operator/vpn.pem", Internal: 7001}
	doc.Resources = append(doc.Resources, BackupResource{Name: "WebSocket entry", Reverse: &web})
	view := source.Metrics.View()
	view.Since = time.Now().UTC()
	view.Counters["F000001"] = Traffic{Received: 500, Sent: 100, LastReceived: 500}
	view.Policies["F000001"] = TrafficPolicy{Label: "Customer", Limit: 10000, Direction: "total"}
	doc.Traffic = &view
	archive, e := sealBackup(doc, "recovery-password")
	if e != nil {
		t.Fatal(e)
	}
	in := BackupInput{Archive: archive, Password: "recovery-password", IncludeTraffic: true, Addresses: map[string]string{"192.0.2.10": "192.0.2.99"}, Interfaces: map[string]string{"tm_in": "eth0"}}
	_, review, e := source.ReviewBackup(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	in.Revision = review.Revision
	result, e := source.RestoreBackup(ctx, in)
	if e != nil {
		t.Fatal(e)
	}
	receipt := result.(map[string]any)
	if receipt["traffic_restored"] != true {
		t.Fatal(receipt)
	}
	cs, _, e := source.state(ctx)
	if e != nil || len(cs) != 1 || cs[0].Enabled || cs[0].Bind != "192.0.2.99" || cs[0].Interface != "eth0" {
		t.Fatal(cs, e)
	}
	if source.Metrics.View().Settings.Enabled || source.Metrics.View().Counters["F000001"].Received != 500 || source.Metrics.View().Counters["F000001"].LastReceived != 0 {
		t.Fatal("traffic continuity lost")
	}
	// Export the restored definitions and prove peer keys/names survive a second
	// migration. No native engine or host networking is needed while paused.
	file, e := source.ExportBackup(ctx, BackupInput{Password: in.Password, IncludeTraffic: true})
	if e != nil {
		t.Fatal(e)
	}
	var exported recoveryDocument
	if e = openBackup(file.Archive, in.Password, &exported); e != nil {
		t.Fatal(e)
	}
	if exported.Counter != 42 || len(exported.Resources) != 3 {
		t.Fatal("recovery counts differ")
	}
	found := false
	for _, r2 := range exported.Resources {
		if r2.Name == "Customer reverse" && r2.Reverse != nil && r2.Reverse.Key == r.Key {
			found = true
		}
	}
	if !found {
		b, _ := json.Marshal(exported)
		t.Fatal("roundtrip lost data", string(b))
	}
	if _, e = source.RestoreBackup(ctx, in); e == nil {
		t.Fatal("restored over occupied installation")
	}
	lock, e := nodeLease(filepath.Join(source.ConfigDir, "manager.lock"))
	if e != nil {
		t.Fatal(e)
	}
	defer lock.Close()
	if _, e = source.ExportBackup(ctx, BackupInput{Password: in.Password}); e == nil {
		t.Fatal("snapshot bypassed manager lock")
	}
}
