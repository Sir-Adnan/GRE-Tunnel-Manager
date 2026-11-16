package release

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func archive(t *testing.T, members map[string]string, extra ...*tar.Header) []byte {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range members {
		if e := tw.WriteHeader(&tar.Header{Name: name, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg}); e != nil {
			t.Fatal(e)
		}
		tw.Write([]byte(body))
	}
	for _, h := range extra {
		tw.WriteHeader(h)
	}
	tw.Close()
	gz.Close()
	return buf.Bytes()
}

func sums(name string, data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]) + "  " + name + "\n"
}

func TestCompareAndValid(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{{"1.6.0", "1.5.3", 1}, {"1.5.3", "1.6.0", -1}, {"1.10.0", "1.9.9", 1}, {"2.0.0", "2.0.0", 0}} {
		if got := Compare(c.a, c.b); got != c.want {
			t.Errorf("Compare(%s,%s)=%d", c.a, c.b, got)
		}
	}
	for _, bad := range []string{"v1.6.0", "1.6", "01.6.0", "1.6.0-rc1", ""} {
		if Valid(bad) {
			t.Errorf("%q accepted", bad)
		}
	}
	if (Check{Current: "1.6.0", Latest: "1.6.1"}).Available() != true || (Check{Current: "1.6.1", Latest: "1.6.0"}).Available() {
		t.Fatal("Available")
	}
}

func TestFetchVerifiesAndUnpacksOnlyFixedMembers(t *testing.T) {
	name := ArchiveName("1.6.0", "amd64")
	data := archive(t, map[string]string{"gtm-panel": "bin", "gre.sh": "engine", "LICENSE": "text"},
		&tar.Header{Name: "../escape", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd"})
	from := t.TempDir()
	os.WriteFile(filepath.Join(from, name), data, 0600)
	os.WriteFile(filepath.Join(from, "SHA256SUMS"), []byte(sums(name, data)), 0600)
	dir := t.TempDir()
	p, e := Client{}.Fetch(context.Background(), "1.6.0", "amd64", from, dir)
	if e != nil {
		t.Fatal(e)
	}
	if got, _ := os.ReadFile(p.Binary); string(got) != "bin" {
		t.Fatal("binary content")
	}
	if info, _ := os.Stat(p.Engine); info.Mode().Perm() != 0700 {
		t.Fatalf("engine mode %v", info.Mode())
	}
	for _, unwanted := range []string{"LICENSE", "escape"} {
		if _, e := os.Lstat(filepath.Join(dir, unwanted)); e == nil {
			t.Fatalf("%s extracted", unwanted)
		}
	}
	if _, e := os.Lstat(filepath.Join(filepath.Dir(dir), "escape")); e == nil {
		t.Fatal("path escaped the directory")
	}
}

func TestVerifyRejectsMismatchDuplicatesAndMissingEntries(t *testing.T) {
	name := ArchiveName("1.6.0", "arm64")
	data := archive(t, map[string]string{"gtm-panel": "bin", "gre.sh": "engine"})
	for label, list := range map[string]string{
		"mismatch":  sums(name, []byte("other")),
		"duplicate": sums(name, data) + sums(name, data),
		"missing":   sums("other.tar.gz", data),
		"malformed": "zz  " + name + "\n",
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, name), data, 0600)
		os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(list), 0600)
		if Verify(dir, name) == nil {
			t.Errorf("%s accepted", label)
		}
	}
}

func TestUnpackRejectsIncompleteOrUnexpectedMembers(t *testing.T) {
	for label, data := range map[string][]byte{
		"missing engine": archive(t, map[string]string{"gtm-panel": "bin"}),
		"linked binary":  archive(t, map[string]string{"gre.sh": "x"}, &tar.Header{Name: "gtm-panel", Typeflag: tar.TypeSymlink, Linkname: "/bin/sh"}),
		"not gzip":       []byte("plain"),
	} {
		dir := t.TempDir()
		path := filepath.Join(dir, "a.tar.gz")
		os.WriteFile(path, data, 0600)
		if _, e := Unpack(path, dir); e == nil {
			t.Errorf("%s accepted", label)
		}
	}
}

func TestLatestAndDownload(t *testing.T) {
	name := ArchiveName("1.6.1", "amd64")
	data := archive(t, map[string]string{"gtm-panel": "bin", "gre.sh": "engine"})
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/api/releases/latest":
			if r.Header.Get("User-Agent") != "gtm-test" {
				w.WriteHeader(400)
			}
			w.Write([]byte(`{"tag_name":"v1.6.1","draft":false,"prerelease":false}`))
		case strings.HasSuffix(r.URL.Path, "/v1.6.1/"+name):
			w.Write(data)
		case strings.HasSuffix(r.URL.Path, "/v1.6.1/SHA256SUMS"):
			w.Write([]byte(sums(name, data)))
		default:
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c := Client{HTTP: server.Client(), API: server.URL + "/api", Download: server.URL + "/dl", UserAgent: "gtm-test"}
	latest, e := c.Latest(context.Background())
	if e != nil || latest != "1.6.1" {
		t.Fatalf("latest %q %v", latest, e)
	}
	if _, e = c.Fetch(context.Background(), "1.6.1", "amd64", "", t.TempDir()); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Fetch(context.Background(), "1.6.2", "amd64", "", t.TempDir()); e == nil || !strings.Contains(e.Error(), "404") {
		t.Fatalf("missing release: %v", e)
	}
}

func TestCheckRecordRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "update.json")
	if c, e := LoadCheck(path); e != nil || c.Latest != "" {
		t.Fatal("missing record should be empty")
	}
	want := Check{Current: "1.6.0", Latest: "1.6.1", Checked: time.Date(2026, 11, 16, 0, 0, 0, 0, time.UTC), Error: strings.Repeat("x", 300)}
	if e := SaveCheck(path, want); e != nil {
		t.Fatal(e)
	}
	got, e := LoadCheck(path)
	if e != nil || got.Latest != "1.6.1" || len(got.Error) != 200 || !got.Checked.Equal(want.Checked) {
		t.Fatalf("%+v %v", got, e)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0600 {
		t.Fatal("record must be root-only")
	}
	os.WriteFile(path, []byte(`{"version":1,"secret":"x"}`), 0600)
	if _, e = LoadCheck(path); e == nil {
		t.Fatal("unknown field accepted")
	}
}
