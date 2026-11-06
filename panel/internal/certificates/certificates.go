// Package certificates validates external TLS material and keeps the last valid
// certificate available during renewal. It neither issues certificates nor runs
// an ACME client, and exposes no private material through its status contract.
package certificates

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"sync"
	"time"
)

const MaxPEMBytes = 1024 * 1024

type Source struct{ Certificate, Key, Host string }

type Status struct {
	Protocol    string    `json:"protocol"`
	Host        string    `json:"host,omitempty"`
	Subject     string    `json:"subject,omitempty"`
	Issuer      string    `json:"issuer,omitempty"`
	NotBefore   time.Time `json:"not_before,omitempty"`
	NotAfter    time.Time `json:"not_after,omitempty"`
	Fingerprint string    `json:"fingerprint,omitempty"`
	SelfSigned  bool      `json:"self_signed"`
	Trusted     bool      `json:"trusted"`
	HostnameOK  bool      `json:"hostname_ok"`
	Loaded      time.Time `json:"loaded,omitempty"`
	LastError   string    `json:"last_error,omitempty"`
}

// ReadPEM accepts ACME clients' regular files and symlinked generations, but
// never streams, devices or an unbounded input. Errors never contain PEM data.
func ReadPEM(path string) ([]byte, error) {
	info, e := os.Stat(path)
	if e != nil || !info.Mode().IsRegular() || info.Size() > MaxPEMBytes {
		return nil, errors.New("certificate material must be a readable regular file under 1 MiB")
	}
	f, e := os.Open(path)
	if e != nil {
		return nil, errors.New("certificate material cannot be opened")
	}
	defer f.Close()
	info, e = f.Stat()
	if e != nil || !info.Mode().IsRegular() || info.Size() > MaxPEMBytes {
		return nil, errors.New("certificate material must be a regular file under 1 MiB")
	}
	b, e := io.ReadAll(io.LimitReader(f, MaxPEMBytes+1))
	if e != nil || len(b) > MaxPEMBytes {
		return nil, errors.New("certificate material could not be read within the size limit")
	}
	return b, nil
}

func Parse(certPEM, keyPEM []byte, host string, now time.Time) (*tls.Certificate, Status, error) {
	status := Status{Protocol: "https", Host: host}
	pair, e := tls.X509KeyPair(certPEM, keyPEM)
	if e != nil || len(pair.Certificate) == 0 {
		return nil, status, errors.New("certificate and private key are invalid or do not match")
	}
	leaf, e := x509.ParseCertificate(pair.Certificate[0])
	if e != nil || leaf.IsCA || now.Before(leaf.NotBefore) || !now.Before(leaf.NotAfter) {
		return nil, status, errors.New("server certificate is invalid, expired or not yet valid")
	}
	if host == "" || leaf.VerifyHostname(host) != nil {
		return nil, status, errors.New("certificate does not cover the configured public host")
	}
	serverUsage := len(leaf.ExtKeyUsage) == 0
	for _, usage := range leaf.ExtKeyUsage {
		serverUsage = serverUsage || usage == x509.ExtKeyUsageServerAuth || usage == x509.ExtKeyUsageAny
	}
	if !serverUsage {
		return nil, status, errors.New("certificate is not valid for TLS server authentication")
	}
	switch key := leaf.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() < 2048 {
			return nil, status, errors.New("RSA server keys must be at least 2048 bits")
		}
	case *ecdsa.PublicKey:
		if key.Curve.Params().BitSize < 256 {
			return nil, status, errors.New("ECDSA server keys must be at least 256 bits")
		}
	}
	intermediates := x509.NewCertPool()
	child := leaf
	for _, raw := range pair.Certificate[1:] {
		cert, e := x509.ParseCertificate(raw)
		if e != nil || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) {
			return nil, status, errors.New("invalid certificate chain")
		}
		if child.CheckSignatureFrom(cert) != nil {
			return nil, status, errors.New("certificate chain is incomplete or out of order")
		}
		intermediates.AddCert(cert)
		child = cert
	}
	_, trustError := leaf.Verify(x509.VerifyOptions{DNSName: host, Intermediates: intermediates, CurrentTime: now})
	sum := sha256.Sum256(leaf.Raw)
	status.Subject, status.Issuer = leaf.Subject.String(), leaf.Issuer.String()
	status.NotBefore, status.NotAfter = leaf.NotBefore, leaf.NotAfter
	status.Fingerprint, status.Trusted, status.HostnameOK = hex.EncodeToString(sum[:]), trustError == nil, true
	status.SelfSigned = string(leaf.RawSubject) == string(leaf.RawIssuer) && leaf.CheckSignature(leaf.SignatureAlgorithm, leaf.RawTBSCertificate, leaf.Signature) == nil
	status.Loaded = now.UTC()
	pair.Leaf = leaf
	return &pair, status, nil
}

type Reloader struct {
	mu     sync.RWMutex
	loadMu sync.Mutex
	source func() (Source, error)
	pair   *tls.Certificate
	status Status
}

func New(source func() (Source, error)) (*Reloader, error) {
	r := &Reloader{source: source}
	return r, r.Reload()
}

func (r *Reloader) Reload() error {
	r.loadMu.Lock()
	defer r.loadMu.Unlock()
	source, e := r.source()
	var certPEM, keyPEM []byte
	var pair *tls.Certificate
	var status Status
	if e == nil {
		certPEM, e = ReadPEM(source.Certificate)
	}
	if e == nil {
		keyPEM, e = ReadPEM(source.Key)
	}
	if e == nil {
		pair, status, e = Parse(certPEM, keyPEM, source.Host, time.Now())
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if e != nil {
		r.status.LastError = "Certificate reload failed; the previous certificate remains loaded."
		return e
	}
	r.pair, r.status = pair, status
	return nil
}

func (r *Reloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.pair == nil {
		return nil, errors.New("no valid server certificate loaded")
	}
	return r.pair, nil
}

func (r *Reloader) Status() Status {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.status
}
