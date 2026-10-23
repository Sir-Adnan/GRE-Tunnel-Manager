package control

import (
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResourceDisplayNamesAreIndependentAndFingerprintBound(t *testing.T) {
	dir := t.TempDir()
	m := &Manager{ConfigDir: dir}
	unit := []byte("[Unit]\nDescription=Technical\n")
	id := "gre-tun-1"
	row := id + "\t" + model.Revision(string(unit)) + "\tCustomer A"
	if e := os.WriteFile(filepath.Join(dir, "resource-names.tsv"), []byte(row+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	names, e := m.resourceNames()
	if e != nil {
		t.Fatal(e)
	}
	r := Resource{ID: id, Name: "Technical"}
	applyResourceName(&r, unit, names[id])
	if r.Name != "Customer A" || r.ID != id || !strings.Contains(r.Revision, ":") {
		t.Fatal(r)
	}
	r.Name = "Technical"
	applyResourceName(&r, []byte("replacement"), names[id])
	if r.Name != "Technical" {
		t.Fatal("stale name attached to replacement", r)
	}
	if e = os.WriteFile(filepath.Join(dir, "resource-names.tsv"), []byte(row+"\n"+row+"\n"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = m.resourceNames(); e == nil {
		t.Fatal("duplicate sidecar rows accepted")
	}
}
