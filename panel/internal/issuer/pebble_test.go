package issuer

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
)

// TestObtainWithPebble runs a real ACME order against Pebble, Let's
// Encrypt's test CA. It needs the pebble binary and its source tree:
//
//	go install github.com/letsencrypt/pebble/v2/cmd/pebble@v2.10.1
//	GTM_PEBBLE=$(go env GOPATH)/bin/pebble \
//	GTM_PEBBLE_SRC=$(go env GOMODCACHE)/github.com/letsencrypt/pebble/v2@v2.10.1 \
//	go test ./internal/issuer -run Pebble -v
func TestObtainWithPebble(t *testing.T) {
	binary, source := os.Getenv("GTM_PEBBLE"), os.Getenv("GTM_PEBBLE_SRC")
	if binary == "" || source == "" {
		t.Skip("set GTM_PEBBLE and GTM_PEBBLE_SRC to run against the Pebble test CA")
	}
	dir := t.TempDir()
	settings := map[string]any{"pebble": map[string]any{
		"listenAddress": "127.0.0.1:14000", "managementListenAddress": "127.0.0.1:15000",
		"certificate": filepath.Join(source, "test/certs/localhost/cert.pem"), "privateKey": filepath.Join(source, "test/certs/localhost/key.pem"),
		"httpPort": 5002, "tlsPort": 5001, "ocspResponderURL": "", "externalAccountBindingRequired": false,
		"keyAlgorithm": "ecdsa",
		"profiles": map[string]any{
			"default":    map[string]any{"description": "default", "validityPeriod": 7776000},
			"shortlived": map[string]any{"description": "short", "validityPeriod": 518400},
		},
	}}
	data, _ := json.Marshal(settings)
	configPath := filepath.Join(dir, "pebble.json")
	if e := os.WriteFile(configPath, data, 0600); e != nil {
		t.Fatal(e)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	command := exec.CommandContext(ctx, binary, "-config", configPath, "-strict")
	command.Env = append(os.Environ(), "PEBBLE_VA_NOSLEEP=1", "PEBBLE_WFE_NONCEREJECT=0", "PEBBLE_AUTHZREUSE=0")
	if e := command.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { command.Process.Kill(); command.Wait() }()
	roots := x509.NewCertPool()
	minica, e := os.ReadFile(filepath.Join(source, "test/certs/pebble.minica.pem"))
	if e != nil || !roots.AppendCertsFromPEM(minica) {
		t.Fatal("pebble minica root", e)
	}
	httpClient := &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots}}}
	directory := "https://127.0.0.1:14000/dir"
	for start := time.Now(); ; time.Sleep(100 * time.Millisecond) {
		if response, e := httpClient.Get(directory); e == nil {
			response.Body.Close()
			break
		}
		if time.Since(start) > 15*time.Second {
			t.Fatal("pebble did not start")
		}
	}
	store := Store{Dir: filepath.Join(dir, "acme"), StatusPath: filepath.Join(dir, "certificate.json"), ConfigPath: configPath}
	key, e := store.AccountKey()
	if e != nil {
		t.Fatal(e)
	}
	for _, attempt := range []string{"first order", "renewal with the same account"} {
		result, e := Obtain(ctx, Request{Directory: directory, Host: "127.0.0.1", Email: "ops@example.com", AccountKey: key, Solver: HTTP01{Address: "127.0.0.1:5002"}, HTTPClient: httpClient, UserAgent: "gtm-panel-test"})
		if e != nil {
			t.Fatal(attempt, e)
		}
		if result.Profile != ShortLived {
			t.Fatal(attempt, "IP certificate did not use the short-lived profile:", result.Profile)
		}
		_, status, e := certificates.Parse(result.CertificatePEM, result.KeyPEM, "127.0.0.1", time.Now())
		if e != nil {
			t.Fatal(attempt, e)
		}
		if lifetime := status.NotAfter.Sub(status.NotBefore); lifetime > 7*24*time.Hour {
			t.Fatal(attempt, "lifetime", lifetime)
		}
		block, _ := pem.Decode(result.CertificatePEM)
		leaf, _ := x509.ParseCertificate(block.Bytes)
		if len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) || len(leaf.DNSNames) != 0 {
			t.Fatal(attempt, "identifiers", leaf.IPAddresses, leaf.DNSNames)
		}
	}
	// Port 80-style validation must fail cleanly when nothing answers.
	_, e = Obtain(ctx, Request{Directory: directory, Host: "127.0.0.2", AccountKey: key, Solver: HTTP01{Address: "127.0.0.1:5002"}, HTTPClient: httpClient})
	if e == nil {
		t.Fatal("validation against an unreachable address succeeded")
	}
	t.Log("expected failure:", e)
}
