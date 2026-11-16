package twofactor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// RFC 6238 appendix B, SHA-1 key "12345678901234567890", last six digits.
const rfcSecret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"

func TestCodeMatchesRFC6238(t *testing.T) {
	for unix, want := range map[int64]string{59: "287082", 1111111109: "081804", 1234567890: "005924", 2000000000: "279037"} {
		got, e := Code(rfcSecret, Step(time.Unix(unix, 0)))
		if e != nil || got != want {
			t.Fatalf("time %d: %q %v, want %s", unix, got, e, want)
		}
	}
	if _, e := Code("not-base32", 1); e == nil {
		t.Fatal("invalid secret accepted")
	}
}

func TestVerifyWindowAndReplay(t *testing.T) {
	now := time.Unix(1111111109, 0)
	step := Step(now)
	previous, _ := Code(rfcSecret, step-1)
	if got, ok := Verify(rfcSecret, previous, now, -1); !ok || got != step-1 {
		t.Fatal("one step of clock drift refused")
	}
	if _, ok := Verify(rfcSecret, previous, now, step-1); ok {
		t.Fatal("a used step was accepted again")
	}
	old, _ := Code(rfcSecret, step-3)
	if _, ok := Verify(rfcSecret, old, now, -1); ok {
		t.Fatal("an old code was accepted")
	}
	for _, bad := range []string{"", "12345", "1234567", "abcdef"} {
		if _, ok := Verify(rfcSecret, bad, now, -1); ok {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestSecretURIAndQR(t *testing.T) {
	s, e := NewSecret()
	if e != nil || !ValidSecret(s) {
		t.Fatal(s, e)
	}
	uri := URI(s, "admin@203.0.113.10")
	if !strings.HasPrefix(uri, "otpauth://totp/GRE%20Tunnel%20Manager:admin@203.0.113.10?") || !strings.Contains(uri, "secret="+s) {
		t.Fatal(uri)
	}
	rows, e := QR(uri)
	if e != nil || len(rows) < 21 || len(rows[0]) != len(rows) || strings.Trim(strings.Join(rows, ""), "01") != "" {
		t.Fatal(len(rows), e)
	}
}

func TestRecoveryCodesAreSingleUse(t *testing.T) {
	codes, hashes, e := NewRecoveryCodes()
	if e != nil || len(codes) != 10 || len(hashes) != 10 {
		t.Fatal(codes, e)
	}
	s := Settings{Version: 1, Secret: rfcSecret, Recovery: hashes, Enabled: time.Now()}
	// Spacing and case do not matter.
	if !s.UseRecovery(" " + strings.ToUpper(codes[3]) + " ") {
		t.Fatal("recovery code refused")
	}
	if s.UseRecovery(codes[3]) || len(s.Recovery) != 9 {
		t.Fatal("recovery code reused")
	}
	if s.UseRecovery("aaaaa-aaaaa") {
		t.Fatal("unknown code accepted")
	}
}

func TestSaveLoadRemove(t *testing.T) {
	dir := t.TempDir()
	path, owner := filepath.Join(dir, "two-factor.json"), filepath.Join(dir, "config.json")
	if e := os.WriteFile(owner, []byte("{}"), 0640); e != nil {
		t.Fatal(e)
	}
	if _, on, e := Load(path); on || e != nil {
		t.Fatal("missing file must mean off", e)
	}
	_, hashes, _ := NewRecoveryCodes()
	want := Settings{Secret: rfcSecret, Recovery: hashes, Enabled: time.Now().UTC().Truncate(time.Second)}
	if e := Save(path, owner, want); e != nil {
		t.Fatal(e)
	}
	got, on, e := Load(path)
	if e != nil || !on || got.Secret != want.Secret || len(got.Recovery) != 10 {
		t.Fatal(got, on, e)
	}
	if info, _ := os.Stat(path); info.Mode().Perm() != 0640 {
		t.Fatal(info.Mode())
	}
	if e := Save(path, owner, Settings{Secret: "short", Enabled: time.Now()}); e == nil {
		t.Fatal("invalid settings saved")
	}
	if e := os.WriteFile(path, []byte(`{"version":1,"secret":"`+rfcSecret+`","recovery":[],"enabled":"2026-01-01T00:00:00Z","extra":1}`), 0640); e != nil {
		t.Fatal(e)
	}
	if _, _, e := Load(path); e == nil {
		t.Fatal("unknown field accepted")
	}
	if e := Remove(path); e != nil {
		t.Fatal(e)
	}
	if e := Remove(path); e != nil {
		t.Fatal("removing twice must succeed", e)
	}
}
