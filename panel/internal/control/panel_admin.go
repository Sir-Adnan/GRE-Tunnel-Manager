package control

// Panel administration through the broker: the HTTPS certificate, the
// one-click update and two-factor sign-in. Every action has a fixed argv or a
// fixed file; nothing here accepts a command, a path or a unit name.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/twofactor"
	"golang.org/x/crypto/bcrypt"
)

// UpdateUnit runs a one-click update (see release.RunUnit).
const UpdateUnit = release.RunUnit

// PanelAdmin is present on the panel broker only (not on Agent brokers).
type PanelAdmin struct {
	ConfigPath    string // config.json
	TwoFactorPath string // two-factor.json
	CheckPath     string // update.json
	RunPath       string // update-run.json
	Binary        string // gtm-panel
	Version       string
	// Latest asks the release server for the newest version.
	Latest func(context.Context) (string, error)
	// Audit records action metadata (never secrets); nil in tests.
	Audit func(Request, error)
	Now   func() time.Time
	// mu serializes two-factor file changes; they bypass the mutation lock
	// so a sign-in never waits behind a long network operation.
	mu sync.Mutex
}

// NewPanelAdmin uses the installed paths.
func NewPanelAdmin(version string, latest func(context.Context) (string, error)) *PanelAdmin {
	return &PanelAdmin{
		ConfigPath: config.DefaultPath, TwoFactorPath: twofactor.Path, CheckPath: release.CheckPath, RunPath: release.RunPath,
		Binary: "/usr/local/bin/gtm-panel", Version: version, Latest: latest,
		Audit: func(r Request, e error) { _ = audit(r, e) },
	}
}

// CertificateInput asks for a Let's Encrypt certificate over port 80.
type CertificateInput struct {
	Host    string `json:"host,omitempty"`
	Email   string `json:"email,omitempty"`
	Staging bool   `json:"staging,omitempty"`
}

// TwoFactorInput carries a new secret with its first code, or the password
// and a code that turn two-factor sign-in off.
type TwoFactorInput struct {
	Secret   string `json:"secret,omitempty"`
	Code     string `json:"code,omitempty"`
	Password string `json:"password,omitempty"`
}

// UpdateView is the update state shown in the panel.
type UpdateView struct {
	Current   string        `json:"current"`
	Check     release.Check `json:"check"`
	Available bool          `json:"available"`
	Running   bool          `json:"running"`
	Run       *release.Run  `json:"run,omitempty"`
}

var emailPattern = regexp.MustCompile(`^[^\s@<>()",;:\\]{1,64}@[a-zA-Z0-9.-]{1,190}\.[a-zA-Z]{2,24}$`)
var logPrefix = regexp.MustCompile(`^[0-9]{4}/[0-9]{2}/[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2} `)

func (a *PanelAdmin) now() time.Time {
	if a.Now != nil {
		return a.Now().UTC()
	}
	return time.Now().UTC()
}

func (a *PanelAdmin) execute(ctx context.Context, runner Runner, r Request) (any, error) {
	switch r.Action {
	case "panel-update":
		return a.updateView(ctx, runner)
	case "panel-update-check":
		return a.checkUpdate(ctx, runner)
	case "panel-update-install":
		return a.installUpdate(ctx, runner)
	case "certificate-issue":
		return a.issue(ctx, runner, r.Certificate)
	case "certificate-renew":
		return a.certificate(ctx, runner, "renew", "--force")
	case "certificate-self-signed":
		return a.certificate(ctx, runner, "self-signed", "--enable-https")
	case "two-factor-enable":
		return a.enableTwoFactor(r.TwoFactor)
	case "two-factor-disable":
		return a.disableTwoFactor(r.TwoFactor)
	case "two-factor-recover":
		return a.recover(r.TwoFactor)
	}
	return nil, errors.New("unknown panel action")
}

func (a *PanelAdmin) updateRunning(ctx context.Context, runner Runner) bool {
	_, e := runner.Run(ctx, "systemctl", []string{"is-active", "--quiet", UpdateUnit}, "")
	return e == nil
}

func (a *PanelAdmin) updateView(ctx context.Context, runner Runner) (UpdateView, error) {
	v := UpdateView{Current: a.Version}
	check, e := release.LoadCheck(a.CheckPath)
	if e != nil {
		return v, e
	}
	// A check made by an older release still compares with this one.
	check.Current = a.Version
	v.Check, v.Available = check, check.Available()
	run, e := release.LoadRun(a.RunPath)
	if e != nil {
		return v, e
	}
	if run.State != "" {
		v.Running = a.updateRunning(ctx, runner)
		if run.State == release.RunRunning && !v.Running {
			// The update process ended without writing its result (a reboot or
			// a killed unit). The installed release is whatever runs now.
			run.State, run.Error = release.RunFailed, "the update was interrupted; check gtm logs update"
		}
		v.Run = &run
	}
	return v, nil
}

func (a *PanelAdmin) checkUpdate(ctx context.Context, runner Runner) (UpdateView, error) {
	if a.Latest == nil {
		return UpdateView{}, errors.New("update checks are unavailable")
	}
	step, cancel := context.WithTimeout(ctx, 30*time.Second)
	latest, e := a.Latest(step)
	cancel()
	record := release.Check{Current: a.Version, Latest: latest, Checked: a.now()}
	if e != nil {
		previous, _ := release.LoadCheck(a.CheckPath)
		record.Latest, record.Error = previous.Latest, e.Error()
	}
	if se := release.SaveCheck(a.CheckPath, record); se != nil {
		return UpdateView{}, se
	}
	if e != nil {
		return UpdateView{}, fmt.Errorf("could not reach the release server: %w", e)
	}
	return a.updateView(ctx, runner)
}

func (a *PanelAdmin) installUpdate(ctx context.Context, runner Runner) (UpdateView, error) {
	v, e := a.updateView(ctx, runner)
	if e != nil {
		return v, e
	}
	if v.Running {
		return v, errors.New("an update is already running")
	}
	if !v.Available || !release.Valid(v.Check.Latest) {
		return v, errors.New("no newer release is known; check for updates first")
	}
	// The update stops and restarts this broker, so it runs in its own unit.
	// It installs exactly the release the panel showed, still verified
	// against the release's published SHA256SUMS.
	args := []string{"--unit=" + UpdateUnit, "--collect", "--quiet", "--description=GRE Tunnel Manager update from the panel",
		"--property=TimeoutStartSec=20min", a.Binary, "gtm", "update", "--yes", "--record", "--version", v.Check.Latest}
	if out, e := runner.Run(ctx, "systemd-run", args, ""); e != nil {
		return v, fmt.Errorf("the update could not start: %s", commandReason(out, e))
	}
	v.Running = true
	v.Run = &release.Run{Version: 1, State: release.RunRunning, From: a.Version, To: v.Check.Latest, Started: a.now()}
	return v, nil
}

// CertificateResult tells the page whether the panel restarts on HTTPS.
type CertificateResult struct {
	Message string `json:"message"`
	Host    string `json:"host,omitempty"`
}

func (a *PanelAdmin) issue(ctx context.Context, runner Runner, in CertificateInput) (CertificateResult, error) {
	in.Host, in.Email = strings.ToLower(strings.TrimSpace(in.Host)), strings.TrimSpace(in.Email)
	if in.Host != "" && (!config.ValidHost(in.Host) || strings.HasPrefix(in.Host, "-")) {
		return CertificateResult{}, errors.New("enter a public IP address or a domain name")
	}
	if ip := net.ParseIP(in.Host); ip != nil && (ip.IsPrivate() || ip.IsLoopback() || ip.IsUnspecified() || ip.IsLinkLocalUnicast()) {
		return CertificateResult{}, errors.New("Let's Encrypt certifies public addresses only")
	}
	if in.Email != "" && (len(in.Email) > 254 || !emailPattern.MatchString(in.Email)) {
		return CertificateResult{}, errors.New("enter a valid email address or leave it empty")
	}
	args := []string{"issue", "--enable-https"}
	if in.Host != "" {
		args = append(args, "--host", in.Host)
	}
	if in.Email != "" {
		args = append(args, "--email", in.Email)
	}
	if in.Staging {
		args = append(args, "--staging")
	}
	result, e := a.certificate(ctx, runner, args...)
	result.Host = in.Host
	return result, e
}

func (a *PanelAdmin) certificate(ctx context.Context, runner Runner, args ...string) (CertificateResult, error) {
	out, e := runner.Run(ctx, a.Binary, append([]string{"certificate"}, args...), "")
	if e != nil {
		return CertificateResult{}, errors.New(commandReason(out, e))
	}
	return CertificateResult{Message: strings.TrimSpace(out)}, nil
}

// commandReason is the reason a command printed last, without the log timestamp.
func commandReason(out string, e error) string {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if line := strings.TrimSpace(logPrefix.ReplaceAllString(lines[i], "")); line != "" {
			if len(line) > 400 {
				line = line[:400]
			}
			return line
		}
	}
	return e.Error()
}

// TwoFactorResult returns recovery codes once, when sign-in is turned on.
type TwoFactorResult struct {
	Recovery  []string `json:"recovery,omitempty"`
	Remaining int      `json:"remaining"`
}

func (a *PanelAdmin) enableTwoFactor(in TwoFactorInput) (result TwoFactorResult, e error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() { a.audit("two-factor-enable", e) }()
	if !twofactor.ValidSecret(in.Secret) {
		return result, errors.New("invalid two-factor secret")
	}
	if _, ok := twofactor.Verify(in.Secret, in.Code, a.now(), -1); !ok {
		return result, errors.New("the code does not match; check the time on your phone and try the next code")
	}
	if _, on, e := twofactor.Load(a.TwoFactorPath); e != nil || on {
		if e == nil {
			e = errors.New("two-factor sign-in is already on; turn it off first")
		}
		return result, e
	}
	codes, hashes, e := twofactor.NewRecoveryCodes()
	if e != nil {
		return result, e
	}
	if e = twofactor.Save(a.TwoFactorPath, a.ConfigPath, twofactor.Settings{Secret: in.Secret, Recovery: hashes, Enabled: a.now()}); e != nil {
		return result, e
	}
	return TwoFactorResult{Recovery: codes, Remaining: len(codes)}, nil
}

func (a *PanelAdmin) disableTwoFactor(in TwoFactorInput) (result TwoFactorResult, e error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() { a.audit("two-factor-disable", e) }()
	c, e := config.Load(a.ConfigPath)
	if e != nil {
		return result, e
	}
	if len(in.Password) > 72 || bcrypt.CompareHashAndPassword([]byte(c.PasswordHash), []byte(in.Password)) != nil {
		return result, errors.New("incorrect password")
	}
	s, on, e := twofactor.Load(a.TwoFactorPath)
	if e != nil {
		return result, e
	}
	if !on {
		return result, nil
	}
	if _, ok := twofactor.Verify(s.Secret, in.Code, a.now(), -1); !ok && !s.UseRecovery(in.Code) {
		return result, errors.New("incorrect code")
	}
	return result, twofactor.Remove(a.TwoFactorPath)
}

func (a *PanelAdmin) recover(in TwoFactorInput) (result TwoFactorResult, e error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	defer func() { a.audit("two-factor-recover", e) }()
	s, on, e := twofactor.Load(a.TwoFactorPath)
	if e != nil {
		return result, e
	}
	if !on || len(in.Code) > 32 || !s.UseRecovery(in.Code) {
		return result, errors.New("incorrect code")
	}
	if e = twofactor.Save(a.TwoFactorPath, a.ConfigPath, s); e != nil {
		return result, e
	}
	return TwoFactorResult{Remaining: len(s.Recovery)}, nil
}

func (a *PanelAdmin) audit(action string, e error) {
	if a.Audit != nil {
		a.Audit(Request{Action: action}, e)
	}
}
