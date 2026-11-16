// Package twofactor implements time-based one-time passwords (RFC 6238:
// SHA-1, six digits, 30-second steps), single-use recovery codes and the
// root-owned settings file that turns two-factor sign-in on.
//
// The file lives beside config.json instead of inside it, so a panel release
// that predates two-factor sign-in can still load its configuration after a
// rollback.
package twofactor

import (
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"rsc.io/qr"
)

// Path is the settings file. Its presence means two-factor sign-in is on.
const Path = "/etc/gre-manager-panel/two-factor.json"

// Issuer names the panel in authenticator apps.
const Issuer = "GRE Tunnel Manager"

const (
	period        = 30
	recoveryCount = 10
	// recoveryAlphabet avoids 0/o, 1/l/i so codes survive being written down.
	recoveryAlphabet = "abcdefghjkmnpqrstuvwxyz23456789"
)

var encoding = base32.StdEncoding.WithPadding(base32.NoPadding)
var secretPattern = regexp.MustCompile(`^[A-Z2-7]{32}$`)
var hashPattern = regexp.MustCompile(`^[a-f0-9]{64}$`)
var codePattern = regexp.MustCompile(`^[0-9]{6}$`)

// NewSecret returns 160 random bits as unpadded base32.
func NewSecret() (string, error) {
	b := make([]byte, 20)
	if _, e := rand.Read(b); e != nil {
		return "", e
	}
	return encoding.EncodeToString(b), nil
}

// ValidSecret reports a secret made by NewSecret.
func ValidSecret(secret string) bool { return secretPattern.MatchString(secret) }

// Step is the 30-second counter for a time.
func Step(t time.Time) int64 { return t.Unix() / period }

// Code returns the six-digit code of one step.
func Code(secret string, step int64) (string, error) {
	key, e := encoding.DecodeString(secret)
	if e != nil || !ValidSecret(secret) {
		return "", errors.New("invalid two-factor secret")
	}
	var counter [8]byte
	binary.BigEndian.PutUint64(counter[:], uint64(step))
	mac := hmac.New(sha1.New, key)
	mac.Write(counter[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	value := binary.BigEndian.Uint32(sum[offset:offset+4]) & 0x7fffffff
	return fmt.Sprintf("%06d", value%1000000), nil
}

// Verify accepts a code of the current step or one step either side (clock
// drift). It returns the matched step; callers reject steps at or before the
// last accepted one so an observed code cannot be replayed.
func Verify(secret, code string, now time.Time, last int64) (int64, bool) {
	code = strings.TrimSpace(code)
	if !codePattern.MatchString(code) {
		return 0, false
	}
	current, matched, ok := Step(now), int64(0), false
	for step := current - 1; step <= current+1; step++ {
		expected, e := Code(secret, step)
		if e != nil {
			return 0, false
		}
		if subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 && step > last && !ok {
			matched, ok = step, true
		}
	}
	return matched, ok
}

// LooksLikeCode reports six digits; anything else is tried as a recovery code.
func LooksLikeCode(code string) bool { return codePattern.MatchString(strings.TrimSpace(code)) }

// URI is the otpauth:// link an authenticator app reads from the QR code.
func URI(secret, account string) string {
	label := url.PathEscape(Issuer + ":" + account)
	q := url.Values{"secret": {secret}, "issuer": {Issuer}, "algorithm": {"SHA1"}, "digits": {"6"}, "period": {"30"}}
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// QR returns the code's modules as rows of '1' (dark) and '0' (light). The
// page draws them; no image or markup crosses the API.
func QR(text string) ([]string, error) {
	c, e := qr.Encode(text, qr.M)
	if e != nil {
		return nil, e
	}
	rows := make([]string, c.Size)
	for y := 0; y < c.Size; y++ {
		var b strings.Builder
		for x := 0; x < c.Size; x++ {
			if c.Black(x, y) {
				b.WriteByte('1')
			} else {
				b.WriteByte('0')
			}
		}
		rows[y] = b.String()
	}
	return rows, nil
}

// NewRecoveryCodes returns ten single-use codes (about 49 bits each) and
// their hashes. Only the hashes are stored.
func NewRecoveryCodes() (codes, hashes []string, e error) {
	for len(codes) < recoveryCount {
		b := make([]byte, 10)
		if _, e = rand.Read(b); e != nil {
			return nil, nil, e
		}
		var s strings.Builder
		for i, v := range b {
			if i == 5 {
				s.WriteByte('-')
			}
			s.WriteByte(recoveryAlphabet[int(v)%len(recoveryAlphabet)])
		}
		codes = append(codes, s.String())
		hashes = append(hashes, HashRecovery(s.String()))
	}
	return codes, hashes, nil
}

// HashRecovery normalizes spacing, dashes and case before hashing.
func HashRecovery(code string) string {
	code = strings.ToLower(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(code)))
	sum := sha256.Sum256([]byte(code))
	return hex.EncodeToString(sum[:])
}

// Settings is the saved state of two-factor sign-in.
type Settings struct {
	Version  int       `json:"version"`
	Secret   string    `json:"secret"`
	Recovery []string  `json:"recovery"`
	Enabled  time.Time `json:"enabled"`
}

func (s Settings) validate() error {
	if s.Version != 1 || !ValidSecret(s.Secret) || len(s.Recovery) > recoveryCount || s.Enabled.IsZero() {
		return errors.New("two-factor settings are damaged")
	}
	for _, h := range s.Recovery {
		if !hashPattern.MatchString(h) {
			return errors.New("two-factor settings are damaged")
		}
	}
	return nil
}

// UseRecovery removes a matching recovery code. Every stored hash is
// compared so timing does not reveal its position.
func (s *Settings) UseRecovery(code string) bool {
	h, found := HashRecovery(code), -1
	for i, stored := range s.Recovery {
		if subtle.ConstantTimeCompare([]byte(stored), []byte(h)) == 1 && found < 0 {
			found = i
		}
	}
	if found < 0 {
		return false
	}
	s.Recovery = append(s.Recovery[:found:found], s.Recovery[found+1:]...)
	return true
}

// Load reads the settings. ok is false when two-factor sign-in is off.
func Load(path string) (s Settings, ok bool, e error) {
	info, e := os.Lstat(path)
	if errors.Is(e, os.ErrNotExist) {
		return s, false, nil
	}
	if e != nil {
		return s, false, e
	}
	if !info.Mode().IsRegular() || info.Size() > 8192 {
		return s, false, errors.New("two-factor settings must be a small regular file")
	}
	f, e := os.Open(path)
	if e != nil {
		return s, false, e
	}
	defer f.Close()
	data, e := io.ReadAll(io.LimitReader(f, 8193))
	if e != nil {
		return s, false, e
	}
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&s) != nil {
		return Settings{}, false, errors.New("two-factor settings are damaged")
	}
	if e = s.validate(); e != nil {
		return Settings{}, false, e
	}
	return s, true, nil
}

// Save writes the settings with the owner and group of ownerPath
// (config.json: root:grepanel), mode 0640, so the panel can verify codes.
func Save(path, ownerPath string, s Settings) error {
	s.Version = 1
	if e := s.validate(); e != nil {
		return e
	}
	data, e := json.MarshalIndent(s, "", "  ")
	if e != nil {
		return e
	}
	return config.SaveShared(path, ownerPath, append(data, '\n'))
}

// Remove turns two-factor sign-in off. A missing file is not an error.
func Remove(path string) error {
	e := os.Remove(path)
	if errors.Is(e, os.ErrNotExist) {
		return nil
	}
	return e
}
