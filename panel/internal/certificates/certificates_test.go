package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func fixture(t *testing.T, serial int64, host string, expiry time.Time) ([]byte, []byte, *x509.Certificate) {
	t.Helper()
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		t.Fatal(e)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, e := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if e != nil {
		t.Fatal(e)
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		t.Fatal(e)
	}
	leaf, e := x509.ParseCertificate(der)
	if e != nil {
		t.Fatal(e)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), leaf
}

func TestValidationAndSafeReload(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	cert, key, _ := fixture(t, 1, "panel.example", time.Now().Add(time.Hour))
	if e := os.WriteFile(certPath, cert, 0600); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(keyPath, key, 0600); e != nil {
		t.Fatal(e)
	}
	r, e := New(func() (Source, error) { return Source{certPath, keyPath, "panel.example"}, nil })
	if e != nil {
		t.Fatal(e)
	}
	initial := r.Status()
	if !initial.HostnameOK || !initial.SelfSigned || initial.Trusted || initial.Fingerprint == "" {
		t.Fatal(initial)
	}
	if _, _, e := Parse(cert, key, "other.example", time.Now()); e == nil {
		t.Fatal("hostname mismatch accepted")
	}
	_, otherKey, _ := fixture(t, 2, "panel.example", time.Now().Add(time.Hour))
	if _, _, e := Parse(cert, otherKey, "panel.example", time.Now()); e == nil {
		t.Fatal("mismatched key accepted")
	}
	expired, expiredKey, _ := fixture(t, 3, "panel.example", time.Now().Add(-time.Minute))
	if _, _, e := Parse(expired, expiredKey, "panel.example", time.Now()); e == nil {
		t.Fatal("expired certificate accepted")
	}
	if e := os.WriteFile(certPath, []byte("broken material"), 0600); e != nil {
		t.Fatal(e)
	}
	if r.Reload() == nil {
		t.Fatal("broken reload accepted")
	}
	if got := r.Status(); got.Fingerprint != initial.Fingerprint || got.LastError == "" {
		t.Fatal(got)
	}
	pair, e := r.GetCertificate(nil)
	if e != nil || pair.Leaf.SerialNumber.Int64() != 1 {
		t.Fatal(pair, e)
	}
	if _, e := ReadPEM(dir); e == nil {
		t.Fatal("directory accepted")
	}
	if e := os.WriteFile(certPath, make([]byte, MaxPEMBytes+1), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadPEM(certPath); e == nil {
		t.Fatal("oversized file accepted")
	}
}

func TestRenewalChangesActualTLSHandshakesAndKeepsOldOnFailure(t *testing.T) {
	dir := t.TempDir()
	bundle := filepath.Join(dir, "https.pem")
	first, key, leaf := fixture(t, 10, "panel.example", time.Now().Add(time.Hour))
	if e := os.WriteFile(bundle, append(first, key...), 0600); e != nil {
		t.Fatal(e)
	}
	r, e := New(func() (Source, error) { return Source{bundle, bundle, "panel.example"}, nil })
	if e != nil {
		t.Fatal(e)
	}
	s := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	s.TLS = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: r.GetCertificate}
	s.StartTLS()
	defer s.Close()
	check := func(want int64, trusted *x509.Certificate) {
		t.Helper()
		roots := x509.NewCertPool()
		roots.AddCert(trusted)
		conn, e := tls.Dial("tcp", s.Listener.Addr().String(), &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: "panel.example"})
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		if got := conn.ConnectionState().PeerCertificates[0].SerialNumber.Int64(); got != want {
			t.Fatalf("got %d want %d", got, want)
		}
	}
	check(10, leaf)
	second, secondKey, secondLeaf := fixture(t, 11, "panel.example", time.Now().Add(2*time.Hour))
	if e := os.WriteFile(bundle, append(second, secondKey...), 0600); e != nil {
		t.Fatal(e)
	}
	if e := r.Reload(); e != nil {
		t.Fatal(e)
	}
	check(11, secondLeaf)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				_, _ = r.GetCertificate(nil)
				_ = r.Status()
			}
		}()
	}
	if e := os.WriteFile(bundle, []byte("incomplete renewal"), 0600); e != nil {
		t.Fatal(e)
	}
	if r.Reload() == nil {
		t.Fatal("incomplete renewal accepted")
	}
	wg.Wait()
	check(11, secondLeaf)
}
