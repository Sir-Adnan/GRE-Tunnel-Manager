package config

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestPasswordCharacterAndByteLimits(t *testing.T) {
	for _, value := range []string{"12345678", "یکرمزبلند", strings.Repeat("a", 72)} {
		if e := ValidatePassword(value); e != nil {
			t.Fatal(e)
		}
	}
	for _, value := range []string{"1234567", strings.Repeat("a", 73), strings.Repeat("ژ", 37), "abcde\nfgh", "abcd\x00efgh", "abcde\x7ffgh", "abcdefg\xff"} {
		if ValidatePassword(value) == nil {
			t.Fatal("invalid password accepted")
		}
	}
}

func TestHostAndURLs(t *testing.T) {
	for _, host := range []string{"panel.example.com", "localhost", "xn--mgbh0fb.example", "127.0.0.1", "2001:db8::1"} {
		if !ValidHost(host) {
			t.Fatal(host)
		}
	}
	for _, host := range []string{"", "0.0.0.0", "::", "224.0.0.1", "255.255.255.255", "999.2.3.4", "host:8443", "[::1]", "https://example.com", "example.com/path", "-host.com", "host..com", "host_.com", "ex ample.com", "مثال.com", "example.com."} {
		if ValidHost(host) {
			t.Fatal(host)
		}
	}
	for _, test := range []struct {
		cfg  Config
		want string
	}{
		{Config{Listen: "0.0.0.0:8443", PublicIP: "203.0.113.1"}, "https://203.0.113.1:8443"},
		{Config{Listen: "[::]:8080", PublicHost: "2001:db8::1", Protocol: "http"}, "http://[2001:db8::1]:8080"},
		{Config{Listen: "0.0.0.0:8443", PublicHost: "panel.example.com"}, "https://panel.example.com:8443"},
		{Config{Listen: "0.0.0.0:8443"}, ""},
	} {
		if got := test.cfg.URL(); got != test.want {
			t.Fatal(got, test.want)
		}
	}
}

func TestOldConfigDefaultsToHTTPSAndDomainCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	cfg, _, e := Create(path, Options{Listen: "127.0.0.1", Port: 0, Username: "admin", Password: "12345678", Protocol: "https", PublicHost: "panel.example.com"})
	if e != nil {
		t.Fatal(e)
	}
	data, _ := os.ReadFile(cfg.Certificate)
	block, _ := pem.Decode(data)
	cert, e := x509.ParseCertificate(block.Bytes)
	if e != nil || cert.VerifyHostname("panel.example.com") != nil {
		t.Fatal("domain SAN missing", e)
	}
	cfg.Protocol = ""
	cfg.PublicHost = ""
	if e = Save(path, cfg, 0640); e != nil {
		t.Fatal(e)
	}
	loaded, e := Load(path)
	if e != nil || loaded.Scheme() != "https" || loaded.Certificate != cfg.Certificate || loaded.PasswordHash != cfg.PasswordHash {
		t.Fatal("old configuration not preserved", e)
	}
	loaded.Protocol = "ftp"
	if loaded.Validate() == nil {
		t.Fatal("invalid transport accepted")
	}
	loaded.Protocol = "http"
	loaded.Certificate = ""
	loaded.PrivateKey = ""
	if e = loaded.Validate(); e != nil {
		t.Fatal(e)
	}
	loaded.Protocol = "https"
	if loaded.Validate() == nil {
		t.Fatal("TLS without cert accepted")
	}
}

func TestExistingCertificateAndTrailingConfigurationAreRejected(t *testing.T) {
	folder := t.TempDir()
	cert := filepath.Join(folder, "server.crt")
	if e := os.WriteFile(cert, []byte("operator-certificate"), 0600); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Create(filepath.Join(folder, "config.json"), Options{Listen: "127.0.0.1", Username: "admin", Password: "12345678", Protocol: "https"}); e == nil {
		t.Fatal("existing certificate overwritten")
	}
	data, _ := os.ReadFile(cert)
	if string(data) != "operator-certificate" {
		t.Fatal("certificate modified")
	}
	path := filepath.Join(t.TempDir(), "config.json")
	if _, _, e := Create(path, Options{Listen: "127.0.0.1", Username: "admin", Password: "12345678", Protocol: "http"}); e != nil {
		t.Fatal(e)
	}
	file, e := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	file.WriteString("{}\n")
	file.Close()
	if _, e = Load(path); e == nil {
		t.Fatal("extra config object accepted")
	}
}

func TestConcurrentInitialSetupCannotReplaceCredentials(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	var group sync.WaitGroup
	var successes int
	var winner string
	var mu sync.Mutex
	start := make(chan struct{})
	for _, secret := range []string{"first-password", "second-password"} {
		group.Add(1)
		go func(secret string) {
			defer group.Done()
			<-start
			cfg, _, e := Create(path, Options{Listen: "127.0.0.1", Username: "admin", Password: secret, Protocol: "http"})
			if e == nil {
				mu.Lock()
				successes++
				winner = cfg.PasswordHash
				mu.Unlock()
			}
		}(secret)
	}
	close(start)
	group.Wait()
	loaded, e := Load(path)
	if e != nil || successes != 1 || loaded.PasswordHash != winner {
		t.Fatal("initial setup overwrote credentials", successes, e)
	}
}
