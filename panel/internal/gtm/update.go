package gtm

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
)

func (a *App) update(ctx context.Context, args []string) (err error) {
	fs := a.flags("update", "Download, verify and install a newer release. If it does not start, the current release is restored. Tunnels keep running.")
	check := fs.Bool("check", false, "Only check whether a newer release exists")
	target := fs.String("version", "", "Install this version (MAJOR.MINOR.PATCH) instead of the latest")
	dir := fs.String("package-dir", "", "Use the archive and SHA256SUMS from this directory (needs --version)")
	force := fs.Bool("force", false, "Reinstall or downgrade even when not newer")
	yes := fs.Bool("yes", false, "Do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "alias of --yes")
	// Set by the panel's one-click update (a transient systemd unit started
	// by the broker); the record tells the panel how the update ended.
	record := fs.Bool("record", false, "")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	latest := *target
	if *record {
		if *check {
			return errors.New("--record cannot be combined with --check")
		}
		path := a.Installer.Layout.Path(release.RunPath)
		run := release.Run{State: release.RunRunning, From: a.Version, Started: time.Now().UTC()}
		if e := release.SaveRun(path, run); e != nil {
			return fmt.Errorf("could not record the update: %w", e)
		}
		defer func() {
			run.To, run.Finished, run.State = latest, time.Now().UTC(), release.RunSucceeded
			if err != nil {
				run.State = release.RunFailed
				if !errors.Is(err, ErrReported) {
					run.Error = err.Error()
				} else {
					run.Error = "the new release did not start; the previous release was restored (gtm logs update)"
				}
			}
			_ = release.SaveRun(path, run)
		}()
	}
	return a.runUpdate(ctx, &latest, *check, *dir, *force, *yes, *record)
}

func (a *App) runUpdate(ctx context.Context, target *string, check bool, dir string, force, yes, strict bool) error {
	if !a.Installer.PanelInstalled() && !a.Installer.AgentInstalled() {
		return errors.New("nothing is installed yet; run gtm install or the install.sh one-liner")
	}
	latest := *target
	defer func() { *target = latest }()
	switch {
	case latest != "" && !release.Valid(latest):
		return errors.New("--version must look like 1.6.0")
	case latest == "" && dir != "":
		return errors.New("--package-dir needs --version")
	case latest == "":
		a.UI.Step("Checking for a newer release")
		var e error
		latest, e = a.checkLatest(ctx)
		if e != nil {
			return fmt.Errorf("could not check for updates: %w", e)
		}
	}
	newer := release.Compare(latest, a.Version) > 0
	if check {
		if newer {
			a.UI.Warn("v%s is available; this server runs v%s", latest, a.Version)
			a.UI.Command("sudo gtm update")
		} else {
			a.UI.Done("v%s is the latest release", a.Version)
		}
		return nil
	}
	if !newer && !force {
		if strict {
			// The panel asked for an update; "nothing to do" is not a success.
			return fmt.Errorf("v%s is not newer than the installed v%s; nothing was changed", latest, a.Version)
		}
		a.UI.Done("Already on v%s; use --force to reinstall", a.Version)
		return nil
	}
	if !yes && (a.UI.Interactive || a.UI.Accessible) {
		proceed := true
		title := fmt.Sprintf("Update v%s → v%s?", a.Version, latest)
		if e := a.UI.Confirm(title, "Panel services restart for a moment; tunnels keep running. A failed start restores this release.", &proceed); e != nil {
			return e
		}
		if !proceed {
			return nil
		}
	}
	arch, e := release.Arch()
	if e != nil {
		return e
	}
	tmp, e := os.MkdirTemp("", "gtm-update-*")
	if e != nil {
		return e
	}
	defer os.RemoveAll(tmp)
	a.UI.Step("Downloading v%s", latest)
	pkg, e := a.Release.Fetch(ctx, latest, arch, dir, tmp)
	if e != nil {
		return e
	}
	if v, e := a.Installer.Host.Run(ctx, pkg.Binary, "version"); e != nil || v != "v"+latest {
		return errors.New("the downloaded package reports a different version; nothing was changed")
	}
	a.UI.Done("Package v%s verified (SHA-256)", latest)
	// The new release installs itself, so its own units and checks apply.
	next := []string{"gtm", "install", "--source", tmp, "--yes"}
	if !a.Installer.PanelInstalled() {
		next = []string{"gtm", "agent", "install", "--source", tmp}
	}
	if e := a.Installer.Host.Stream(ctx, pkg.Binary, next...); e != nil {
		// The new release already explained what happened.
		return ErrReported
	}
	return nil
}

// checkLatest asks GitHub for the newest release and records the answer for
// the menu and the panel.
func (a *App) checkLatest(ctx context.Context) (string, error) {
	latest, e := a.Release.Latest(ctx)
	record := release.Check{Current: a.Version, Latest: latest, Checked: time.Now().UTC()}
	if e != nil {
		record = release.Check{Current: a.Version, Checked: time.Now().UTC(), Error: e.Error()}
		if previous, le := release.LoadCheck(a.Installer.Layout.Path(release.CheckPath)); le == nil && previous.Latest != "" {
			record.Latest = previous.Latest
		}
	}
	if regularDir(a.Installer.Layout.Path(install.StateDir)) {
		_ = release.SaveCheck(a.Installer.Layout.Path(release.CheckPath), record)
	}
	return latest, e
}

// updateCheck runs from the daily timer. It only records the answer.
func (a *App) updateCheck(ctx context.Context, args []string) error {
	if len(args) != 0 {
		return errors.New("update-check takes no arguments")
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	latest, e := a.checkLatest(ctx)
	if e != nil {
		return e
	}
	if release.Compare(latest, a.Version) > 0 {
		fmt.Fprintf(a.UI.Out(), "v%s is available (installed v%s). Install it with: sudo gtm update\n", latest, a.Version)
	}
	return nil
}

func regularDir(path string) bool {
	info, e := os.Lstat(path)
	return e == nil && info.IsDir()
}
