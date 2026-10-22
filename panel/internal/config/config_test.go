package config

import (
	"crypto/x509"
	"encoding/pem"
	"golang.org/x/crypto/bcrypt"
	"os"
	"path/filepath"
	"testing"
)

func TestSetupRandomPortHashAndCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, fingerprint, e := New(path, "127.0.0.1", 0, "admin", "a-secure-password-123", []string{"203.0.113.10", "2001:db8::10"})
	if e != nil {
		t.Fatal(e)
	}
	if len(fingerprint) != 64 || c.Listen == "127.0.0.1:0" {
		t.Fatal(c)
	}
	loaded, e := Load(path)
	if e != nil {
		t.Fatal(e)
	}
	if e = bcrypt.CompareHashAndPassword([]byte(loaded.PasswordHash), []byte("a-secure-password-123")); e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(c.Certificate)
	block, _ := pem.Decode(data)
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil {
		t.Fatal(e)
	}
	if e = cert.VerifyHostname("203.0.113.10"); e != nil {
		t.Fatal(e)
	}
	if e = cert.VerifyHostname("2001:db8::10"); e != nil {
		t.Fatal(e)
	}
}
func TestBadCredentialsRejected(t *testing.T) {
	for _, user := range []string{"root;id", "a", "../../x"} {
		if _, _, e := New(filepath.Join(t.TempDir(), "config.json"), "127.0.0.1", 0, user, "a-secure-password-123", nil); e == nil {
			t.Fatal(user)
		}
	}
}
