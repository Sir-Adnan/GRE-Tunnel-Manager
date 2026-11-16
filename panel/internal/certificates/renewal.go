package certificates

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"time"
)

// RenewalPath is written by the root certificate command and read by the
// public panel (root:grepanel 0640). It never holds keys, tokens or e-mail.
const RenewalPath = "/etc/gre-manager-panel/certificate.json"

const (
	SourceSelfSigned  = "self-signed"
	SourceLetsEncrypt = "letsencrypt"
	SourceACME        = "acme" // another ACME directory
	SourceExternal    = "external"
)

// Renewal describes where the panel certificate comes from and, when the
// panel renews it itself, when the next attempt starts and how the last went.
type Renewal struct {
	Version     int       `json:"version"`
	Source      string    `json:"source"`
	Host        string    `json:"host,omitempty"`
	Challenge   string    `json:"challenge,omitempty"`
	Profile     string    `json:"profile,omitempty"`
	Staging     bool      `json:"staging,omitempty"`
	AutoRenew   bool      `json:"auto_renew"`
	Issued      time.Time `json:"issued,omitzero"`
	NotAfter    time.Time `json:"not_after,omitzero"`
	RenewAfter  time.Time `json:"renew_after,omitzero"`
	LastAttempt time.Time `json:"last_attempt,omitzero"`
	LastError   string    `json:"last_error,omitempty"`
}

// RenewAfter is the start of the last third of a certificate's lifetime:
// about 30 days before expiry for 90-day certificates and two days before
// for six-day IP certificates.
func RenewAfter(notBefore, notAfter time.Time) time.Time {
	return notAfter.Add(-notAfter.Sub(notBefore) / 3)
}

func LoadRenewal(path string) (Renewal, error) {
	var value Renewal
	info, e := os.Lstat(path)
	if e != nil {
		return value, e
	}
	if !info.Mode().IsRegular() || info.Size() > 64*1024 {
		return value, errors.New("certificate status must be a small regular file")
	}
	data, e := os.ReadFile(path)
	if e != nil {
		return value, e
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if e = decoder.Decode(&value); e != nil {
		return value, errors.New("certificate status is unreadable")
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		return value, errors.New("certificate status is unreadable")
	}
	return value, nil
}
