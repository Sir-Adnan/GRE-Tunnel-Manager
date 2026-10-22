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
	"io"
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
	Protocol     string `json:"protocol,omitempty"`
	PublicHost   string `json:"public_host,omitempty"`
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
	if c.Protocol != "" && c.Protocol != "https" && c.Protocol != "http" {
		return errors.New("protocol must be https or http")
	}
	if c.PublicHost != "" && !ValidHost(c.PublicHost) {
		return errors.New("public host must be an IP address or ASCII domain")
	}
	if !UserPattern.MatchString(c.Username) {
		return errors.New("username must be 3–40 ASCII letters, digits, dots, dashes or underscores")
	}
	cost, e := bcrypt.Cost([]byte(c.PasswordHash))
	if e != nil || cost < 12 {
		return errors.New("invalid password hash")
	}
	if (c.Scheme() == "https" && (!filepath.IsAbs(c.Certificate) || !filepath.IsAbs(c.PrivateKey))) || !path.IsAbs(c.BrokerSocket) || c.Version != 1 {
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
	var extra any
	if d.Decode(&extra) != io.EOF {
		return c, errors.New("one configuration object required")
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
	return Create(path, Options{Listen: host, Port: port, Username: user, Password: password, Protocol: "https", Addresses: ips})
}

type Options struct {
	Listen, Username, Password, Protocol, PublicHost string
	Port                                             int
	Addresses                                        []string
}

func Create(path string, o Options) (Config, string, error) {
	var c Config
	if !UserPattern.MatchString(o.Username) {
		return c, "", errors.New("username must be 3–40 ASCII letters, digits, dots, dashes or underscores")
	}
	if e := ValidatePassword(o.Password); e != nil {
		return c, "", e
	}
	if o.Protocol != "https" && o.Protocol != "http" {
		return c, "", errors.New("protocol must be https or http")
	}
	if o.PublicHost != "" && !ValidHost(o.PublicHost) {
		return c, "", errors.New("invalid public address")
	}
	if _, e := os.Lstat(path); !os.IsNotExist(e) {
		return c, "", errors.New("configuration already exists or cannot be inspected")
	}
	if net.ParseIP(o.Listen) == nil || o.Port < 0 || o.Port > 65535 {
		return c, "", errors.New("invalid address or port")
	}
	listener, e := net.Listen("tcp", net.JoinHostPort(o.Listen, fmt.Sprint(o.Port)))
	if e != nil {
		return c, "", e
	}
	address := listener.Addr().String()
	listener.Close()
	if e = os.MkdirAll(filepath.Dir(path), 0750); e != nil {
		return c, "", e
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(o.Password), 12)
	if e != nil {
		return c, "", e
	}
	c = Config{Version: 1, Listen: address, Username: o.Username, PasswordHash: string(hash), BrokerSocket: Socket, Protocol: o.Protocol, PublicHost: o.PublicHost}
	if net.ParseIP(o.PublicHost) != nil {
		c.PublicIP = o.PublicHost
	}
	fingerprint := ""
	if o.Protocol == "https" {
		c.Certificate = filepath.Join(filepath.Dir(path), "server.crt")
		c.PrivateKey = filepath.Join(filepath.Dir(path), "server.key")
		for _, name := range []string{c.Certificate, c.PrivateKey} {
			if _, e := os.Lstat(name); !os.IsNotExist(e) {
				return c, "", errors.New("certificate files already exist or cannot be inspected; preserve or relocate them before setup")
			}
		}
		fingerprint, e = certificate(c.Certificate, c.PrivateKey, append(o.Addresses, o.PublicHost))
		if e != nil {
			return c, "", e
		}
	}
	// O_EXCL also protects direct, concurrent `gtm-panel setup` invocations;
	// the initial existence check alone is not a no-overwrite guarantee.
	data, e := json.MarshalIndent(c, "", "  ")
	if e != nil {
		return c, "", e
	}
	if e = writeNew(path, append(data, '\n'), 0640); e != nil {
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
		} else if ValidHost(address) {
			t.DNSNames = append(t.DNSNames, address)
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
	if e = writeNew(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0640); e != nil {
		return "", e
	}
	if e = writeNew(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0644); e != nil {
		os.Remove(keyPath)
		return "", e
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, e := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if e != nil {
		return e
	}
	_, e = file.Write(data)
	if e == nil {
		e = file.Sync()
	}
	if closeError := file.Close(); e == nil {
		e = closeError
	}
	if e != nil {
		os.Remove(path)
	}
	return e
}
