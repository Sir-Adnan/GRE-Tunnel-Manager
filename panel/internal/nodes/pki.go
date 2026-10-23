package nodes

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"time"
)

func randomID() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func newKey() (*ecdsa.PrivateKey, []byte, error) {
	k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return nil, nil, e
	}
	b, e := x509.MarshalPKCS8PrivateKey(k)
	if e != nil {
		return nil, nil, e
	}
	return k, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: b}), nil
}
func serial() *big.Int {
	n, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		panic(e)
	}
	if n.Sign() == 0 {
		n.SetInt64(1)
	}
	return n
}
func certificate(template, parent *x509.Certificate, pub any, key any) ([]byte, error) {
	b, e := x509.CreateCertificate(rand.Reader, template, parent, pub, key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: b}), nil
}
func parseCert(data []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(data)
	if b == nil || b.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate")
	}
	return x509.ParseCertificate(b.Bytes)
}
func newAuthority() ([]byte, []byte, error) {
	k, key, e := newKey()
	if e != nil {
		return nil, nil, e
	}
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: "GTM Node Authority"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign, MaxPathLenZero: true}
	crt, e := certificate(t, t, &k.PublicKey, k)
	return crt, key, e
}
func sign(caPEM, keyPEM []byte, csrPEM []byte, id, host string) ([]byte, string, error) {
	ca, e := parseCert(caPEM)
	if e != nil {
		return nil, "", e
	}
	pair, e := tls.X509KeyPair(caPEM, keyPEM)
	if e != nil {
		return nil, "", e
	}
	b, _ := pem.Decode(csrPEM)
	if b == nil {
		return nil, "", errors.New("invalid CSR")
	}
	csr, e := x509.ParseCertificateRequest(b.Bytes)
	if e != nil || csr.CheckSignature() != nil {
		return nil, "", errors.New("invalid CSR signature")
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, "", errors.New("P-256 key required")
	}
	t := &x509.Certificate{SerialNumber: serial(), Subject: pkix.Name{CommonName: id}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().Add(30 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
	if host != "" {
		t.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		t.NotAfter = time.Now().AddDate(1, 0, 0)
		if ip := net.ParseIP(host); ip != nil {
			t.IPAddresses = []net.IP{ip}
		} else {
			t.DNSNames = []string{host}
		}
	}
	crt, e := certificate(t, ca, csr.PublicKey, pair.PrivateKey)
	return crt, t.SerialNumber.String(), e
}
func makeCSR(key *ecdsa.PrivateKey) ([]byte, error) {
	b, e := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{}, key)
	if e != nil {
		return nil, e
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: b}), nil
}
