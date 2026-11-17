package control

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/twofactor"
	"golang.org/x/crypto/bcrypt"
)

// adminRunner records argv and answers by command name.
type adminRunner struct {
	calls  []string
	active bool   // systemctl is-active of the update unit
	fail   string // command name that fails
	out    string
}

func (r *adminRunner) Run(_ context.Context, name string, args []string, _ string) (string, error) {
	r.calls = append(r.calls, name+" "+strings.Join(args, " "))
	if name == "systemctl" {
		if r.active {
			return "", nil
		}
		return "", errors.New("inactive")
	}
	if name == r.fail {
		return r.out, errors.New("operation failed: exit status 1")
	}
	return r.out, nil
}

func newAdmin(t *testing.T) (*PanelAdmin, *adminRunner) {
	t.Helper()
	dir := t.TempDir()
	a := &PanelAdmin{
		ConfigPath: filepath.Join(dir, "config.json"), TwoFactorPath: filepath.Join(dir, "two-factor.json"),
		CheckPath: filepath.Join(dir, "update.json"), RunPath: filepath.Join(dir, "update-run.json"),
		Binary: "/usr/local/bin/gtm-panel", Version: "1.6.0",
		Latest: func(context.Context) (string, error) { return "1.6.1", nil },
	}
	return a, &adminRunner{}
}

func TestCertificateIssueBuildsFixedArguments(t *testing.T) {
	a, runner := newAdmin(t)
	if _, e := a.execute(context.Background(), runner, Request{Action: "certificate-issue", Certificate: CertificateInput{Host: " Panel.Example.com ", Email: "ops@example.com", Staging: true}}); e != nil {
		t.Fatal(e)
	}
	want := "/usr/local/bin/gtm-panel certificate issue --enable-https --host panel.example.com --email ops@example.com --staging"
	if len(runner.calls) != 1 || runner.calls[0] != want {
		t.Fatal(runner.calls)
	}
	for _, in := range []CertificateInput{{Host: "--config=/tmp/x"}, {Host: "10.0.0.5"}, {Host: "127.0.0.1"}, {Host: "a b"}, {Email: "not-an-email"}, {Email: "a@b.c --staging"}} {
		if _, e := a.execute(context.Background(), runner, Request{Action: "certificate-issue", Certificate: in}); e == nil {
			t.Fatalf("%+v accepted", in)
		}
	}
	if len(runner.calls) != 1 {
		t.Fatal("refused input reached a command", runner.calls)
	}
	runner.fail, runner.out = "/usr/local/bin/gtm-panel", "Requesting a certificate\n2026/11/16 10:00:00 port 80 is in use; free it or use the Cloudflare DNS challenge\n"
	_, e := a.execute(context.Background(), runner, Request{Action: "certificate-renew"})
	if e == nil || e.Error() != "port 80 is in use; free it or use the Cloudflare DNS challenge" {
		t.Fatal(e)
	}
	if runner.calls[len(runner.calls)-1] != "/usr/local/bin/gtm-panel certificate renew --force" {
		t.Fatal(runner.calls)
	}
}

func TestUpdateCheckAndInstall(t *testing.T) {
	a, runner := newAdmin(t)
	ctx := context.Background()
	if _, e := a.execute(ctx, runner, Request{Action: "panel-update-install"}); e == nil {
		t.Fatal("installed without a known newer release")
	}
	v, e := a.execute(ctx, runner, Request{Action: "panel-update-check"})
	if e != nil || !v.(UpdateView).Available || v.(UpdateView).Check.Latest != "1.6.1" {
		t.Fatal(v, e)
	}
	if info, _ := os.Stat(a.CheckPath); info.Mode().Perm() != 0600 {
		t.Fatal("update record must be root-only")
	}
	runner.calls = nil
	v, e = a.execute(ctx, runner, Request{Action: "panel-update-install"})
	if e != nil || !v.(UpdateView).Running {
		t.Fatal(v, e)
	}
	start := runner.calls[len(runner.calls)-1]
	if !strings.HasPrefix(start, "systemd-run --unit="+UpdateUnit+" --collect") || !strings.HasSuffix(start, "/usr/local/bin/gtm-panel gtm update --yes --record --version 1.6.1") {
		t.Fatal(start)
	}
	// A record left "running" by a process that no longer runs is reported
	// as interrupted, and a running unit refuses a second start.
	_ = release.SaveRun(a.RunPath, release.Run{State: release.RunRunning, From: "1.6.0", Started: time.Now()})
	v, _ = a.execute(ctx, runner, Request{Action: "panel-update"})
	if run := v.(UpdateView).Run; run == nil || run.State != release.RunFailed || !strings.Contains(run.Error, "interrupted") {
		t.Fatal(v)
	}
	runner.active = true
	if _, e = a.execute(ctx, runner, Request{Action: "panel-update-install"}); e == nil || !strings.Contains(e.Error(), "already running") {
		t.Fatal(e)
	}
	// A failed check keeps the last known release.
	runner.active = false
	a.Latest = func(context.Context) (string, error) { return "", errors.New("timeout") }
	if _, e = a.execute(ctx, runner, Request{Action: "panel-update-check"}); e == nil {
		t.Fatal("failed check reported success")
	}
	if c, _ := release.LoadCheck(a.CheckPath); c.Latest != "1.6.1" || c.Error != "timeout" {
		t.Fatal(c)
	}
}

func TestTwoFactorEnableRecoverDisable(t *testing.T) {
	a, runner := newAdmin(t)
	ctx := context.Background()
	if _, _, e := config.Create(a.ConfigPath, config.Options{Listen: "127.0.0.1", Port: 2053, Username: "admin", Password: "long-example-password", Protocol: "http"}); e != nil {
		t.Fatal(e)
	}
	secret, _ := twofactor.NewSecret()
	if _, e := a.execute(ctx, runner, Request{Action: "two-factor-enable", TwoFactor: TwoFactorInput{Secret: secret, Code: "000000"}}); e == nil {
		// One in a million: the random secret's current code may be 000000.
		if code, _ := twofactor.Code(secret, twofactor.Step(time.Now())); code != "000000" {
			t.Fatal("wrong code enabled two-factor sign-in")
		}
	}
	code, _ := twofactor.Code(secret, twofactor.Step(time.Now()))
	result, e := a.execute(ctx, runner, Request{Action: "two-factor-enable", TwoFactor: TwoFactorInput{Secret: secret, Code: code}})
	if e != nil {
		t.Fatal(e)
	}
	codes := result.(TwoFactorResult).Recovery
	if len(codes) != 10 {
		t.Fatal(result)
	}
	if _, e = a.execute(ctx, runner, Request{Action: "two-factor-enable", TwoFactor: TwoFactorInput{Secret: secret, Code: code}}); e == nil {
		t.Fatal("enabled twice")
	}
	result, e = a.execute(ctx, runner, Request{Action: "two-factor-recover", TwoFactor: TwoFactorInput{Code: codes[0]}})
	if e != nil || result.(TwoFactorResult).Remaining != 9 {
		t.Fatal(result, e)
	}
	if _, e = a.execute(ctx, runner, Request{Action: "two-factor-recover", TwoFactor: TwoFactorInput{Code: codes[0]}}); e == nil {
		t.Fatal("recovery code reused")
	}
	if _, e = a.execute(ctx, runner, Request{Action: "two-factor-disable", TwoFactor: TwoFactorInput{Password: "wrong-password-here", Code: codes[1]}}); e == nil {
		t.Fatal("disabled without the password")
	}
	if _, e = a.execute(ctx, runner, Request{Action: "two-factor-disable", TwoFactor: TwoFactorInput{Password: "long-example-password", Code: "aaaaa-aaaaa"}}); e == nil {
		t.Fatal("disabled without a valid code")
	}
	if _, e = a.execute(ctx, runner, Request{Action: "two-factor-disable", TwoFactor: TwoFactorInput{Password: "long-example-password", Code: codes[1]}}); e != nil {
		t.Fatal(e)
	}
	if _, on, _ := twofactor.Load(a.TwoFactorPath); on {
		t.Fatal("still on")
	}
	if len(runner.calls) != 0 {
		t.Fatal("two-factor changes must not run commands", runner.calls)
	}
}

func TestPanelActionsAreClassified(t *testing.T) {
	for _, action := range []string{"panel-update-check", "panel-update-install", "certificate-issue", "certificate-renew", "certificate-self-signed"} {
		if !PublicOperation(action) {
			t.Fatal(action, "must be a job")
		}
	}
	for _, action := range []string{"two-factor-enable", "two-factor-disable", "two-factor-recover", "panel-password"} {
		if PublicOperation(action) || !LightAction(action) {
			t.Fatal(action, "must use its dedicated sign-in route")
		}
	}
	if !ReadAction("panel-update") {
		t.Fatal("panel-update is a read")
	}
	if _, e := (&Manager{Runner: &adminRunner{}}).Execute(context.Background(), Request{Action: "certificate-renew"}); e == nil {
		t.Fatal("an Agent broker ran a panel action")
	}
}

func TestChangePasswordChecksCurrentAndCode(t *testing.T) {
	a, runner := newAdmin(t)
	ctx := context.Background()
	if _, _, e := config.Create(a.ConfigPath, config.Options{Listen: "127.0.0.1", Port: 38653, Username: "admin", Password: "long-example-password", Protocol: "http"}); e != nil {
		t.Fatal(e)
	}
	change := func(in PasswordInput) error {
		_, e := a.execute(ctx, runner, Request{Action: "panel-password", Password: in})
		return e
	}
	for _, in := range []PasswordInput{
		{Current: "wrong-password-here", Next: "brand-new-password"},
		{Current: "long-example-password", Next: "short"},
		{Current: "long-example-password", Next: "long-example-password"},
	} {
		if change(in) == nil {
			t.Fatal("accepted", in.Next)
		}
	}
	// With two-factor sign-in on, a code is required; a refused new password
	// never spends a recovery code.
	secret, _ := twofactor.NewSecret()
	code, _ := twofactor.Code(secret, twofactor.Step(time.Now()))
	result, e := a.execute(ctx, runner, Request{Action: "two-factor-enable", TwoFactor: TwoFactorInput{Secret: secret, Code: code}})
	if e != nil {
		t.Fatal(e)
	}
	codes := result.(TwoFactorResult).Recovery
	if change(PasswordInput{Current: "long-example-password", Next: "brand-new-password"}) == nil {
		t.Fatal("changed without a code")
	}
	if change(PasswordInput{Current: "long-example-password", Next: "short", Code: codes[0]}) == nil {
		t.Fatal("accepted a short password")
	}
	if e = change(PasswordInput{Current: "long-example-password", Next: "brand-new-password", Code: codes[0]}); e != nil {
		t.Fatal(e)
	}
	s, _, _ := twofactor.Load(a.TwoFactorPath)
	if len(s.Recovery) != 9 {
		t.Fatal("recovery code not spent exactly once", len(s.Recovery))
	}
	c, e := config.Load(a.ConfigPath)
	if e != nil || c.Username != "admin" || !strings.HasSuffix(c.Listen, ":38653") || bcrypt.CompareHashAndPassword([]byte(c.PasswordHash), []byte("brand-new-password")) != nil {
		t.Fatal("password not saved or other settings changed", e)
	}
	if len(runner.calls) != 0 {
		t.Fatal("a password change must not run commands", runner.calls)
	}
}
