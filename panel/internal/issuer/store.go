package issuer

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
)

const (
	ChallengeHTTP       = "http-01"
	ChallengeCloudflare = "cloudflare"
)

// Settings is the root-only renewal recipe in Store.Dir. The e-mail address
// stays here; the public status record never contains it.
type Settings struct {
	Version     int    `json:"version"`
	Host        string `json:"host"`
	Email       string `json:"email,omitempty"`
	Directory   string `json:"directory"`
	Challenge   string `json:"challenge"`
	Profile     string `json:"profile,omitempty"`
	HTTPAddress string `json:"http_address,omitempty"`
}

func (s Settings) Validate() error {
	if s.Version != 1 || !config.ValidHost(s.Host) {
		return errors.New("certificate settings need a valid public host")
	}
	if u, e := url.Parse(s.Directory); e != nil || u.Scheme != "https" || u.Host == "" {
		return errors.New("the ACME directory must be an https URL")
	}
	switch s.Challenge {
	case ChallengeHTTP:
	case ChallengeCloudflare:
		if net.ParseIP(s.Host) != nil {
			return errors.New("IP certificates are validated over HTTP (port 80), not DNS")
		}
	default:
		return errors.New("challenge must be http-01 or cloudflare")
	}
	if s.Email != "" && !ValidEmail(s.Email) {
		return errors.New("invalid e-mail address")
	}
	if s.Profile != "" && !profilePattern(s.Profile) {
		return errors.New("invalid certificate profile name")
	}
	if s.HTTPAddress != "" {
		if _, _, e := net.SplitHostPort(s.HTTPAddress); e != nil {
			return errors.New("invalid HTTP validation address")
		}
	}
	return nil
}

// Source names who issues the certificate, for the status record.
func (s Settings) Source() string {
	if s.Directory == LetsEncrypt || s.Directory == LetsEncryptStaging {
		return certificates.SourceLetsEncrypt
	}
	return certificates.SourceACME
}

type Store struct {
	Dir        string // root-only: settings, account key, DNS token
	StatusPath string // root:grepanel 0640, beside the panel configuration
	ConfigPath string // ownership template for StatusPath
}

func DefaultStore() Store {
	return Store{Dir: "/etc/gre-manager-panel/acme", StatusPath: certificates.RenewalPath, ConfigPath: config.DefaultPath}
}

func (s Store) settingsPath() string { return filepath.Join(s.Dir, "settings.json") }
func (s Store) keyPath() string      { return filepath.Join(s.Dir, "account.key") }
func (s Store) tokenPath() string    { return filepath.Join(s.Dir, "cloudflare.token") }

func (s Store) ensureDir() error {
	if e := os.MkdirAll(s.Dir, 0700); e != nil {
		return e
	}
	info, e := os.Lstat(s.Dir)
	if e != nil || !info.IsDir() {
		return errors.New("certificate account directory must be a real directory")
	}
	return os.Chmod(s.Dir, 0700)
}

// Settings reports whether managed renewal is configured.
func (s Store) Settings() (Settings, bool, error) {
	var value Settings
	data, e := readSmall(s.settingsPath())
	if os.IsNotExist(e) {
		return value, false, nil
	}
	if e != nil {
		return value, false, e
	}
	if e = strictJSON(data, &value); e != nil {
		return value, false, errors.New("certificate settings are unreadable")
	}
	return value, true, value.Validate()
}

func (s Store) SaveSettings(value Settings) error {
	if e := value.Validate(); e != nil {
		return e
	}
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	if e = s.ensureDir(); e != nil {
		return e
	}
	return writeAtomic(s.settingsPath(), append(data, '\n'), 0600)
}

// AccountKey loads the ACME account key, creating it on first use.
func (s Store) AccountKey() (crypto.Signer, error) {
	if e := s.ensureDir(); e != nil {
		return nil, e
	}
	data, e := readSmall(s.keyPath())
	if os.IsNotExist(e) {
		key, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			return nil, e
		}
		raw, e := x509.MarshalPKCS8PrivateKey(key)
		if e != nil {
			return nil, e
		}
		return key, writeAtomic(s.keyPath(), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: raw}), 0600)
	}
	if e != nil {
		return nil, e
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, errors.New("ACME account key is unreadable")
	}
	parsed, e := x509.ParsePKCS8PrivateKey(block.Bytes)
	signer, ok := parsed.(crypto.Signer)
	if e != nil || !ok {
		return nil, errors.New("ACME account key is unreadable")
	}
	return signer, nil
}

func (s Store) Token() (string, error) {
	data, e := readSmall(s.tokenPath())
	if e != nil {
		return "", errors.New("the saved Cloudflare token is missing; issue the certificate again with a token")
	}
	return strings.TrimSpace(string(data)), nil
}

func (s Store) SaveToken(token string) error {
	if !ValidToken(token) {
		return errors.New("the Cloudflare API token looks invalid")
	}
	if e := s.ensureDir(); e != nil {
		return e
	}
	return writeAtomic(s.tokenPath(), []byte(token+"\n"), 0600)
}

// Disable stops managed renewal. The account key stays so a later issue
// reuses the same ACME account; the DNS token is removed.
func (s Store) Disable() error {
	for _, path := range []string{s.settingsPath(), s.tokenPath()} {
		if e := os.Remove(path); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	return nil
}

func (s Store) Record() (certificates.Renewal, error) {
	return certificates.LoadRenewal(s.StatusPath)
}

func (s Store) SaveRecord(value certificates.Renewal) error {
	value.Version = 1
	if len(value.LastError) > 400 {
		value.LastError = value.LastError[:400]
	}
	data, e := json.MarshalIndent(value, "", "  ")
	if e != nil {
		return e
	}
	return config.SaveMaterial(s.StatusPath, s.ConfigPath, append(data, '\n'))
}

func ValidEmail(value string) bool {
	at := strings.LastIndexByte(value, '@')
	if len(value) > 254 || at < 1 || at == len(value)-1 || strings.Count(value, "@") != 1 || strings.ContainsAny(value, " \t\r\n<>(),;:\"[]\\") {
		return false
	}
	return config.ValidHost(value[at+1:]) && net.ParseIP(value[at+1:]) == nil
}

// ValidToken accepts the printable, URL-safe shape of Cloudflare API tokens
// without echoing the value anywhere.
func ValidToken(value string) bool {
	if len(value) < 20 || len(value) > 200 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}

func profilePattern(value string) bool {
	if len(value) > 40 {
		return false
	}
	for _, ch := range value {
		if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_') {
			return false
		}
	}
	return true
}

func readSmall(path string) ([]byte, error) {
	info, e := os.Lstat(path)
	if e != nil {
		return nil, e
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return nil, errors.New(filepath.Base(path) + " must be a small regular file")
	}
	return os.ReadFile(path)
}

func strictJSON(data []byte, value any) error {
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if e := decoder.Decode(value); e != nil {
		return e
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return errors.New("one JSON object required")
	}
	return nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	f, e := os.CreateTemp(filepath.Dir(path), ".panel-*")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(data)
	}
	if e == nil {
		e = f.Sync()
	}
	if closeError := f.Close(); e == nil {
		e = closeError
	}
	if e == nil {
		e = os.Rename(f.Name(), path)
	}
	return e
}
