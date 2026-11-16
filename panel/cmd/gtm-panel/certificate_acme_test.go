package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/issuer"
)

func TestPublicIdentifierRejectsNamesNoPublicCACanValidate(t *testing.T) {
	for _, host := range []string{"203.0.113.10", "2001:db8::10", "panel.example.com"} {
		if e := publicIdentifier(host); e != nil {
			t.Error(host, e)
		}
	}
	for _, host := range []string{"10.0.0.5", "192.168.1.2", "127.0.0.1", "fd00::1", "localhost", "panel.local", "panel"} {
		if publicIdentifier(host) == nil {
			t.Error("accepted", host)
		}
	}
}

func TestCloudflareTokenComesFromAFileOrTheEnvironmentOnly(t *testing.T) {
	t.Setenv(CloudflareTokenEnv, "")
	if _, e := cloudflareToken(""); e == nil || !strings.Contains(e.Error(), CloudflareTokenEnv) {
		t.Fatal(e)
	}
	t.Setenv(CloudflareTokenEnv, "  env-token-abcdefghijklmnopqrstu \n")
	if token, e := cloudflareToken(""); e != nil || token != "env-token-abcdefghijklmnopqrstu" {
		t.Fatal(token, e)
	}
	file := filepath.Join(t.TempDir(), "token")
	os.WriteFile(file, []byte("file-token-abcdefghijklmnopqrst\n"), 0600)
	if token, e := cloudflareToken(file); e != nil || token != "file-token-abcdefghijklmnopqrst" {
		t.Fatal(token, e)
	}
	os.WriteFile(file, []byte("not a token"), 0600)
	if _, e := cloudflareToken(file); e == nil || strings.Contains(e.Error(), "not a token") {
		t.Fatal("invalid token accepted or echoed", e)
	}
}

func TestFailureHintsNameTheNextStep(t *testing.T) {
	base := errors.New("connection refused")
	http := withHint(issuer.Settings{Challenge: issuer.ChallengeHTTP, Host: "203.0.113.4"}, base)
	if !errors.Is(http, base) || !strings.Contains(http.Error(), "port 80 on 203.0.113.4") {
		t.Fatal(http)
	}
	dns := withHint(issuer.Settings{Challenge: issuer.ChallengeCloudflare, Host: "panel.example.com"}, base)
	if !strings.Contains(dns.Error(), "DNS → Edit") {
		t.Fatal(dns)
	}
}

func TestApplyCertificateSwitchesHostsAndRenewalTimingFollowsTheInstalledCertificate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	c, _, e := config.Create(path, config.Options{Listen: "127.0.0.1", Username: "admin", Password: "test-password-12345", Protocol: "http", PublicHost: "203.0.113.20"})
	if e != nil {
		t.Fatal(e)
	}
	if _, ok := currentRenewAfter(c); ok {
		t.Fatal("HTTP panel has no certificate to renew")
	}
	certPEM, keyPEM, _, e := config.SelfSigned([]string{"panel.example.com"})
	if e != nil {
		t.Fatal(e)
	}
	ch := change{configPath: path, host: "panel.example.com", certPEM: certPEM, keyPEM: keyPEM}
	if _, e = applyCertificate(context.Background(), ch); e == nil || !strings.Contains(e.Error(), "--enable-https") {
		t.Fatal("HTTP panel switched without --enable-https", e)
	}
	ch.enableHTTPS = true
	status, e := applyCertificate(context.Background(), ch)
	if e != nil {
		t.Fatal(e)
	}
	installed, e := config.Load(path)
	if e != nil || installed.Scheme() != "https" || installed.PublicHost != "panel.example.com" || status.Host != "panel.example.com" {
		t.Fatal(installed, status, e)
	}
	renewAfter, ok := currentRenewAfter(installed)
	if !ok || !renewAfter.Equal(certificates.RenewAfter(status.NotBefore, status.NotAfter)) {
		t.Fatal(renewAfter, ok)
	}
	if lifetime := status.NotAfter.Sub(status.NotBefore); status.NotAfter.Sub(renewAfter) != lifetime/3 {
		t.Fatal("renewal is not in the last third of the lifetime")
	}
	other, otherKey, _, _ := config.SelfSigned([]string{"other.example.com"})
	if _, e = applyCertificate(context.Background(), change{configPath: path, certPEM: other, keyPEM: otherKey}); e == nil {
		t.Fatal("certificate for another host installed")
	}
	if after, _ := config.Load(path); after != installed {
		t.Fatal("failed install changed the configuration")
	}
}

func TestStatusRecordIsReadableBesideTheConfigurationAndHoldsNoSecrets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if _, _, e := config.New(path, "127.0.0.1", 0, "admin", "test-password-12345", nil); e != nil {
		t.Fatal(e)
	}
	store := storeFor(path)
	if store.Dir != filepath.Join(dir, "acme") || store.StatusPath != filepath.Join(dir, "certificate.json") {
		t.Fatal(store)
	}
	now := time.Now().UTC().Truncate(time.Second)
	saveRecord(store, certificates.Renewal{Source: certificates.SourceLetsEncrypt, Host: "panel.example.com", Challenge: issuer.ChallengeCloudflare, AutoRenew: true, NotAfter: now.Add(90 * 24 * time.Hour), LastError: strings.Repeat("x", 900)})
	record, e := certificates.LoadRenewal(store.StatusPath)
	if e != nil || record.Version != 1 || !record.AutoRenew || len(record.LastError) != 400 || !record.NotAfter.Equal(now.Add(90*24*time.Hour)) {
		t.Fatal(record, e)
	}
	data, _ := os.ReadFile(store.StatusPath)
	for _, field := range []string{"email", "token", "key"} {
		if strings.Contains(string(data), field) {
			t.Fatal("status record mentions", field)
		}
	}
}

func TestCertificateHelpListsEveryCommand(t *testing.T) {
	for _, command := range []string{"status", "issue", "renew", "install", "self-signed"} {
		if !strings.Contains(certificateUsage, "  "+command) {
			t.Error(command)
		}
	}
	if e := certificateCommand(context.Background(), []string{"bogus"}); e == nil {
		t.Fatal("unknown command accepted")
	}
}
