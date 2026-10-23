package control

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestVersionParsingAndCompatibility(t *testing.T) {
	for _, test := range []struct{ id, text, version, status string }{
		{"haproxy", "HAProxy version 2.8.5-1ubuntu3 2024/04/01\nStatus: stable", "2.8.5-1ubuntu3", "native_required"},
		{"haproxy", "HAProxy version 2.0.1", "2.0.1", "unsupported"},
		{"realm", "realm 2.9.6", "2.9.6", "pinned"}, {"realm", "realm 2.9.5", "2.9.5", "unverified"},
		{"realm", "realm 3.0.0", "3.0.0", "unsupported"}, {"realm", "unrelated 2.9.6", "", "unknown"},
		{"frp", "0.71.1\n", "0.71.1", "pinned"}, {"frp", "error 0.71.1", "", "unknown"},
		{"rathole", "rathole\nBuild Version: 0.5.0\n", "0.5.0", "pinned"},
		{"nftables", "nftables v1.0.9 (Old Doc Yak)", "1.0.9", "native_required"},
		{"iptables", "iptables v1.8.10 (nf_tables)", "1.8.10", "native_required"},
	} {
		v := parseEngineVersion(test.id, test.text)
		if v != test.version || compatibility(test.id, v) != test.status {
			t.Fatalf("%s: %q / %q", test.id, v, compatibility(test.id, v))
		}
	}
}

type versionRunner struct {
	count  int
	server string
}

func (r *versionRunner) Run(_ context.Context, name string, args []string, input string) (string, error) {
	r.count++
	if filepath.Base(name) == "frps" {
		return r.server, nil
	}
	return "0.71.1", nil
}

func TestVersionCacheInvalidatesOnBinaryChangeAndReportsPeerMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("executable lookup fixture uses Linux file modes")
	}
	dir := t.TempDir()
	t.Setenv("PATH", dir)
	for _, name := range []string{"frpc", "frps"} {
		if e := os.WriteFile(filepath.Join(dir, name), []byte("test executable"), 0755); e != nil {
			t.Fatal(e)
		}
	}
	r := &versionRunner{server: "0.71.1"}
	m := &Manager{Runner: r}
	first := m.components(context.Background())
	if r.count != 2 || first[4].Compatibility != "pinned" {
		t.Fatal(first, r.count)
	}
	m.components(context.Background())
	if r.count != 2 {
		t.Fatal("cache missed")
	}
	r.server = "0.70.0"
	if e := os.WriteFile(filepath.Join(dir, "frps"), []byte("changed test executable"), 0755); e != nil {
		t.Fatal(e)
	}
	changed := m.components(context.Background())
	if r.count != 4 || changed[4].Compatibility != "mismatch" {
		t.Fatal(changed, r.count)
	}
	changed[4].Version = "bad caller mutation"
	if m.components(context.Background())[4].Version != "0.71.1" {
		t.Fatal("cache slice leaked")
	}
}
