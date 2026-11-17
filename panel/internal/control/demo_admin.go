package control

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/twofactor"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/version"
)

// demoAdmin simulates certificates, updates and two-factor sign-in in memory.
type demoAdmin struct {
	current, latest string
	checked         time.Time
	run             *release.Run
	runEnds         time.Time
	twoFactor       *twofactor.Settings
}

const demoPassword = "demo-panel-12345"

func nextPatch(v string) string {
	parts := strings.Split(v, ".")
	if len(parts) != 3 {
		return v
	}
	n, e := strconv.Atoi(parts[2])
	if e != nil {
		return v
	}
	return fmt.Sprintf("%s.%s.%d", parts[0], parts[1], n+1)
}

func (d *Demo) adminDemo(r Request) (json.RawMessage, error) {
	now := time.Now().UTC()
	if d.admin == nil {
		d.admin = &demoAdmin{current: version.Number, latest: nextPatch(version.Number), checked: now.Add(-2 * time.Hour)}
	}
	a := d.admin
	if a.run != nil && a.run.State == release.RunRunning && now.After(a.runEnds) {
		a.run.State, a.run.Finished, a.current = release.RunSucceeded, now, a.latest
		d.inventory.Version = a.latest
	}
	view := func() (json.RawMessage, error) {
		check := release.Check{Version: 1, Current: a.current, Latest: a.latest, Checked: a.checked}
		v := UpdateView{Current: a.current, Check: check, Available: check.Available(), Run: a.run, Running: a.run != nil && a.run.State == release.RunRunning}
		return json.Marshal(v)
	}
	switch r.Action {
	case "panel-update":
		return view()
	case "panel-update-check":
		a.checked = now
		return view()
	case "panel-update-install":
		if a.current == a.latest {
			return nil, errors.New("no newer release is known; check for updates first")
		}
		if a.run != nil && a.run.State == release.RunRunning {
			return nil, errors.New("an update is already running")
		}
		a.run, a.runEnds = &release.Run{Version: 1, State: release.RunRunning, From: a.current, To: a.latest, Started: now}, now.Add(6*time.Second)
		return view()
	case "certificate-issue", "certificate-renew", "certificate-self-signed":
		return json.Marshal(CertificateResult{Message: "Demo: no certificate was requested and the panel was not changed.", Host: r.Certificate.Host})
	case "two-factor-enable":
		if a.twoFactor != nil {
			return nil, errors.New("two-factor sign-in is already on; turn it off first")
		}
		if !twofactor.ValidSecret(r.TwoFactor.Secret) {
			return nil, errors.New("invalid two-factor secret")
		}
		if _, ok := twofactor.Verify(r.TwoFactor.Secret, r.TwoFactor.Code, now, -1); !ok {
			return nil, errors.New("the code does not match; check the time on your phone and try the next code")
		}
		codes, hashes, e := twofactor.NewRecoveryCodes()
		if e != nil {
			return nil, e
		}
		a.twoFactor = &twofactor.Settings{Version: 1, Secret: r.TwoFactor.Secret, Recovery: hashes, Enabled: now}
		return json.Marshal(TwoFactorResult{Recovery: codes, Remaining: len(codes)})
	case "two-factor-disable":
		if r.TwoFactor.Password != demoPassword {
			return nil, errors.New("incorrect password")
		}
		if a.twoFactor != nil {
			if _, ok := twofactor.Verify(a.twoFactor.Secret, r.TwoFactor.Code, now, -1); !ok && !a.twoFactor.UseRecovery(r.TwoFactor.Code) {
				return nil, errors.New("incorrect code")
			}
		}
		a.twoFactor = nil
		return json.Marshal(TwoFactorResult{})
	case "panel-password":
		// The demo checks the same rules but keeps its password, so the
		// documented demo sign-in always works after a restart.
		if e := config.ValidatePassword(r.Password.Next); e != nil {
			return nil, e
		}
		if r.Password.Current != demoPassword {
			return nil, errors.New("incorrect password")
		}
		if r.Password.Next == r.Password.Current {
			return nil, errors.New("choose a password different from the current one")
		}
		if a.twoFactor != nil {
			if _, ok := twofactor.Verify(a.twoFactor.Secret, r.Password.Code, now, -1); !ok && !a.twoFactor.UseRecovery(r.Password.Code) {
				return nil, errors.New("incorrect code")
			}
		}
		return json.Marshal(map[string]bool{"ok": true})
	case "two-factor-recover":
		if a.twoFactor == nil || !a.twoFactor.UseRecovery(r.TwoFactor.Code) {
			return nil, errors.New("incorrect code")
		}
		return json.Marshal(TwoFactorResult{Remaining: len(a.twoFactor.Recovery)})
	}
	return nil, errors.New("unknown panel action")
}
