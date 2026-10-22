package config

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
)

const DefaultPath = "/etc/gre-manager-panel/config.json"
const Socket = "/run/gre-manager-panel/broker.sock"

type Config struct {
	Version      int    `json:"version"`
	Listen       string `json:"listen"`
	Username     string `json:"username"`
	PasswordHash string `json:"password_hash"`
	Certificate  string `json:"certificate"`
	PrivateKey   string `json:"private_key"`
	BrokerSocket string `json:"broker_socket"`
	PublicIP     string `json:"public_ip,omitempty"`
}

var UserPattern = regexp.MustCompile(`^[a-zA-Z0-9_.-]{3,40}$`)

func (c Config) Validate() error {
	host, port, e := net.SplitHostPort(c.Listen)
	if e != nil || net.ParseIP(host) == nil || port == "0" {
		return errors.New("invalid listen address")
	}
	portNumber, e := strconv.Atoi(port)
	if e != nil || portNumber < 1 || portNumber > 65535 {
		return errors.New("invalid listen port")
	}
	if c.PublicIP != "" && net.ParseIP(c.PublicIP) == nil {
		return errors.New("invalid public IP")
	}
	if !UserPattern.MatchString(c.Username) {
		return errors.New("username must be 3–40 ASCII letters, digits, dots, dashes or underscores")
	}
	cost, e := bcrypt.Cost([]byte(c.PasswordHash))
	if e != nil || cost < 12 {
		return errors.New("invalid password hash")
	}
	if !filepath.IsAbs(c.Certificate) || !filepath.IsAbs(c.PrivateKey) || !path.IsAbs(c.BrokerSocket) || c.Version != 1 {
		return errors.New("invalid panel configuration")
	}
	return nil
}
func Load(path string) (Config, error) {
	var c Config
	f, e := os.Open(path)
	if e != nil {
		return c, e
	}
	defer f.Close()
	d := json.NewDecoder(f)
	d.DisallowUnknownFields()
	if e = d.Decode(&c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func Save(path string, value any, mode os.FileMode) error {
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	data = append(data, '\n')
	f, e := os.CreateTemp(filepath.Dir(path), ".panel-*")
	if e != nil {
		return e
	}
	name := f.Name()
	defer os.Remove(name)
	if e = preserveOwner(f, path); e != nil {
		f.Close()
		return e
	}
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	ce := f.Close()
	if e == nil {
		e = ce
	}
	if e == nil {
		e = os.Rename(name, path)
	}
	return e
}
func New(path, host string, port int, user, password string, ips []string) (Config, string, error) {
	var c Config
	if !UserPattern.MatchString(user) || len(password) < 12 || len(password) > 72 {
		return c, "", errors.New("use a valid username and a password of 12–72 bytes")
	}
	if net.ParseIP(host) == nil || port < 0 || port > 65535 {
		return c, "", errors.New("invalid address or port")
	}
	listener, e := net.Listen("tcp", net.JoinHostPort(host, fmt.Sprint(port)))
	if e != nil {
		return c, "", e
	}
	address := listener.Addr().String()
	listener.Close()
	if e = os.MkdirAll(filepath.Dir(path), 0750); e != nil {
		return c, "", e
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(password), 12)
	if e != nil {
		return c, "", e
	}
	c = Config{Version: 1, Listen: address, Username: user, PasswordHash: string(hash), Certificate: filepath.Join(filepath.Dir(path), "server.crt"), PrivateKey: filepath.Join(filepath.Dir(path), "server.key"), BrokerSocket: Socket}
	fingerprint, e := certificate(c.Certificate, c.PrivateKey, ips)
	if e != nil {
		return c, "", e
	}
	if e = Save(path, c, 0640); e != nil {
		return c, "", e
	}
	return c, fingerprint, nil
}
func certificate(certPath, keyPath string, addresses []string) (string, error) {
	key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if e != nil {
		return "", e
	}
	serial, e := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if e != nil {
		return "", e
	}
	t := x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "GRE Tunnel Manager"}, NotBefore: time.Now().Add(-5 * time.Minute), NotAfter: time.Now().AddDate(1, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true}
	t.DNSNames = []string{"localhost"}
	t.IPAddresses = []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	for _, address := range addresses {
		if ip := net.ParseIP(address); ip != nil {
			t.IPAddresses = append(t.IPAddresses, ip)
		}
	}
	der, e := x509.CreateCertificate(rand.Reader, &t, &t, &key.PublicKey, key)
	if e != nil {
		return "", e
	}
	raw, e := x509.MarshalPKCS8PrivateKey(key)
	if e != nil {
		return "", e
	}
	if e = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0640); e != nil {
		return "", e
	}
	if e = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		return "", e
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}
