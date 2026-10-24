package control

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func backupFixture(t *testing.T) recoveryDocument {
	t.Helper()
	cs, _, e := model.ParseState(stateFixture())
	if e != nil {
		t.Fatal(e)
	}
	return recoveryDocument{Version: 1, Created: time.Now().UTC(), ManagerVersion: "1.3.2", Host: "source", Counter: 42, Connections: cs, Resources: []BackupResource{{Name: "GRE link", GRE: &GRE{ID: 2, Role: "iran", Bind: "192.0.2.10", Remote: "198.51.100.10", MTU: 1430}}}}
}
func TestBackupAuthenticatedEnvelope(t *testing.T) {
	doc := backupFixture(t)
	const pass = "recovery-only-password"
	archive, e := sealBackup(doc, pass)
	if e != nil {
		t.Fatal(e)
	}
	if strings.Contains(archive, "192.0.2.10") || strings.Contains(archive, "GRE link") {
		t.Fatal("plaintext in archive")
	}
	other, _ := sealBackup(doc, pass)
	if archive == other {
		t.Fatal("nonrandom encryption")
	}
	var restored recoveryDocument
	if e = openBackup(archive, pass, &restored); e != nil || restored.Counter != 42 || restored.Resources[0].GRE.Role != "iran" {
		t.Fatal(e, restored)
	}
	if openBackup(archive, "wrong-password", &restored) == nil {
		t.Fatal("wrong password accepted")
	}
	var env backupEnvelope
	json.Unmarshal([]byte(archive), &env)
	env.Payload[0] ^= 1
	bad, _ := json.Marshal(env)
	if openBackup(string(bad), pass, &restored) == nil {
		t.Fatal("tampering accepted")
	}
	env.Version = 2
	bad, _ = json.Marshal(env)
	if openBackup(string(bad), pass, &restored) == nil {
		t.Fatal("future envelope accepted")
	}
	if _, e = sealBackup(doc, "short"); e == nil {
		t.Fatal("short password")
	}
	if _, e = sealBackup(doc, "رمزکم"); e == nil {
		t.Fatal("UTF-8 bytes counted as characters")
	}
}
func TestRecoveryMigrationAndPausedPayload(t *testing.T) {
	doc := backupFixture(t)
	archive, _ := sealBackup(doc, "recovery-password")
	input := BackupInput{Archive: archive, Password: "recovery-password", Addresses: map[string]string{"192.0.2.10": "192.0.2.99"}, Interfaces: map[string]string{"tm_in": "eth0"}}
	next, review, e := prepareRecovery(input)
	if e != nil {
		t.Fatal(e)
	}
	if next.Connections[0].Bind != "192.0.2.99" || next.Resources[0].GRE.Bind != "192.0.2.99" || next.Connections[0].Interface != "eth0" {
		t.Fatal("mapping lost")
	}
	if len(review.Items) != 2 || len(review.Addresses) < 3 {
		t.Fatal(review)
	}
	payload, e := recoveryPayload(next, strings.Repeat("a", 64)+":0")
	if e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(payload, "I\t42\n") || !strings.Contains(payload, "\tsingle\t0\tmasquerade\teth0\t") {
		t.Fatal("restore must pause and preserve counter", payload)
	}
	input.Addresses = map[string]string{"192.0.2.10": "2001:db8::1"}
	if _, _, e = prepareRecovery(input); e == nil {
		t.Fatal("family migration accepted")
	}
	doc.Resources = append(doc.Resources, doc.Resources[0])
	input.Archive, _ = sealBackup(doc, input.Password)
	input.Addresses = nil
	if _, _, e = prepareRecovery(input); e == nil {
		t.Fatal("duplicate identity accepted")
	}
}
func TestRecoveryRejectsInvalidTrafficAndFutureSchema(t *testing.T) {
	doc := backupFixture(t)
	d := NewDemo()
	view := cloneMetrics(d.metrics)
	view.Counters["F000001"] = Traffic{Received: 1, BaselineReceived: 2}
	doc.Traffic = &view
	in := BackupInput{Password: "recovery-password"}
	in.Archive, _ = sealBackup(doc, in.Password)
	if _, _, e := prepareRecovery(in); e == nil {
		t.Fatal("invalid traffic baseline")
	}
	doc.Traffic = nil
	doc.Version = 2
	in.Archive, _ = sealBackup(doc, in.Password)
	if _, _, e := prepareRecovery(in); e == nil {
		t.Fatal("future schema")
	}
}
func TestDemoBackupRecoveryPreservesSettingsAndRefusesOverwrite(t *testing.T) {
	ctx := context.Background()
	d := NewDemo()
	original := d.inventory.Connections[0]
	d.metrics.Counters[original.ID] = Traffic{Received: 1000, Sent: 200, LastReceived: 1000}
	d.metrics.Policies[original.ID] = TrafficPolicy{Label: "Customer", Limit: 9000, Direction: "total"}
	in := BackupInput{Password: "recovery-password", IncludeTraffic: true}
	data, e := d.Do(ctx, Request{Action: "backup-export", Backup: in})
	if e != nil {
		t.Fatal(e)
	}
	var file BackupDownload
	json.Unmarshal(data, &file)
	in.Archive = file.Archive
	data, e = d.Do(ctx, Request{Action: "backup-review", Backup: in})
	if e != nil {
		t.Fatal(e)
	}
	var review BackupReview
	json.Unmarshal(data, &review)
	in.Revision = review.Revision
	if _, e = d.Do(ctx, Request{Action: "backup-restore", Backup: in}); e == nil {
		t.Fatal("overwrite allowed")
	}
	d.inventory.Connections = []model.Connection{}
	d.metrics.Counters = map[string]Traffic{}
	d.metrics.Policies = map[string]TrafficPolicy{}
	data, _ = d.Do(ctx, Request{Action: "backup-review", Backup: in})
	json.Unmarshal(data, &review)
	if in.Revision == review.Revision {
		t.Fatal("stale target revision unchanged")
	}
	in.Revision = review.Revision
	if _, e = d.Do(ctx, Request{Action: "backup-restore", Backup: in}); e != nil {
		t.Fatal(e)
	}
	c := d.inventory.Connections[0]
	if c.ID != original.ID || c.Name != original.Name || c.Enabled {
		t.Fatal(c)
	}
	if d.metrics.Settings.Enabled || d.metrics.Counters[c.ID].Received != 1000 || d.metrics.Policies[c.ID].Label != "Customer" {
		t.Fatal("accounting lost")
	}
}

func TestRecoveredServiceBootActionIsScoped(t *testing.T) {
	runner := &fakeRunner{}
	root := t.TempDir()
	os.WriteFile(filepath.Join(root, "gre-tun-1.service"), []byte("fixture"), 0600)
	os.WriteFile(filepath.Join(root, "gtm-F000001.service"), []byte("fixture"), 0600)
	m := Manager{Runner: runner, UnitDir: root}
	if _, e := m.Execute(context.Background(), Request{Action: "service", Service: "gre-tun-1", Verb: "enable"}); e != nil {
		t.Fatal(e)
	}
	if len(runner.calls) != 1 || !strings.HasPrefix(runner.calls[0], "systemctl enable --now gre-tun-1\n") {
		t.Fatal(runner.calls)
	}
	if _, e := m.Execute(context.Background(), Request{Action: "service", Service: "gtm-F000001", Verb: "enable"}); e == nil {
		t.Fatal("forward bypassed desired enabled state")
	}
	if _, e := m.Execute(context.Background(), Request{Action: "service", Service: "gre-tun-1", Verb: "unmask"}); e == nil {
		t.Fatal("unknown verb accepted")
	}
}
