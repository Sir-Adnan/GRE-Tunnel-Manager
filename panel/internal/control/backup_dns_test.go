package control

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
)

func TestDomainBackupPreservesPoliciesWithoutTreatingNamesAsMigrationIPs(t *testing.T) {
	cs, _, e := model.ParseState(domainRow())
	if e != nil {
		t.Fatal(e)
	}
	dir := t.TempDir()
	m := &Manager{ConfigDir: dir}
	if e = os.WriteFile(filepath.Join(dir, "dns-policy.tsv"), []byte("a.example\t15\tfirst\nunused.example\t5\tall\n"), 0600); e != nil {
		t.Fatal(e)
	}
	policies, e := m.backupDNSPolicies(cs)
	if e != nil || len(policies) != 1 || policies[0].Mode != "first" {
		t.Fatal(policies, e)
	}
	doc := recoveryDocument{Version: 1, Created: time.Now(), Connections: cs, DNSPolicies: policies}
	validated, view, e := validateRecovery(doc, BackupInput{})
	if e != nil {
		t.Fatal(e)
	}
	for _, ip := range view.Addresses {
		if ip == "a.example" {
			t.Fatal("domain offered as an IP mapping")
		}
	}
	payload, e := recoveryPayload(validated, strings.Repeat("a", 64))
	if e != nil || !strings.Contains(payload, "D\ta.example\t15\tfirst\n") {
		t.Fatal(payload, e)
	}
	for _, bad := range [][]DNSPolicy{{{Name: "other.example", Every: 5, Mode: "all"}}, {{Name: "a.example", Every: 0, Mode: "all"}}, {policies[0], policies[0]}} {
		doc.DNSPolicies = bad
		if _, _, e = validateRecovery(doc, BackupInput{}); e == nil {
			t.Fatal("invalid DNS policy accepted", bad)
		}
	}
}
