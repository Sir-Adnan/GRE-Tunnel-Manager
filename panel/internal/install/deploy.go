package install

import (
	"context"
	"os"
	"path/filepath"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
)

// previousRelease is a private copy of the installed executable and engine,
// kept only until the new release proves healthy.
type previousRelease struct {
	dir            string
	binary, engine string
}

func (p previousRelease) available() bool { return p.dir != "" }

func (p previousRelease) discard() {
	if p.dir != "" {
		os.RemoveAll(p.dir)
	}
}

func (in *Installer) snapshot() (previousRelease, error) {
	l := in.Layout
	if !regular(l.Path(Binary)) || !regular(l.Path(Engine)) {
		return previousRelease{}, nil
	}
	dir, e := os.MkdirTemp("", "gtm-previous-*")
	if e != nil {
		return previousRelease{}, e
	}
	p := previousRelease{dir: dir, binary: filepath.Join(dir, "gtm-panel"), engine: filepath.Join(dir, "manager.sh")}
	if e = copyFileAtomic(l.Path(Binary), p.binary, 0755); e == nil {
		e = copyFileAtomic(l.Path(Engine), p.engine, 0700)
	}
	if e != nil {
		p.discard()
		return previousRelease{}, e
	}
	return p, nil
}

// deploy stops the given units (when installed) and puts the package in
// place. Files already identical to the package are not rewritten.
func (in *Installer) deploy(ctx context.Context, p release.Package, units []string) error {
	l, r := in.Layout, in.report()
	binary, engine := l.Path(Binary), l.Path(Engine)
	if sameFile(p.Binary, binary) && sameFile(p.Engine, engine) {
		if e := in.stopUnits(ctx, units); e != nil {
			return e
		}
		r.Done("Release files are current")
		return nil
	}
	if e := in.stopUnits(ctx, units); e != nil {
		return e
	}
	r.Step("Installing the release files")
	if e := os.MkdirAll(l.Path(LibDir), 0755); e != nil {
		return e
	}
	if !sameFile(p.Binary, binary) {
		if e := copyFileAtomic(p.Binary, binary, 0755); e != nil {
			return e
		}
	}
	if !sameFile(p.Engine, engine) {
		if e := copyFileAtomic(p.Engine, engine, 0700); e != nil {
			return e
		}
	}
	r.Done("Release files installed")
	return nil
}

// stopUnits stops only installed units; a fresh host has nothing to stop.
func (in *Installer) stopUnits(ctx context.Context, units []string) error {
	var present []string
	for _, u := range units {
		if regular(in.Layout.Unit(u)) {
			present = append(present, u)
		}
	}
	if len(present) == 0 {
		return nil
	}
	_, e := in.Host.Run(ctx, "systemctl", append([]string{"stop"}, present...)...)
	return e
}

// rollback restores the previous files and restarts the units. It reports
// whether the previous release is running again.
func (in *Installer) rollback(ctx context.Context, p previousRelease, units []string) bool {
	if !p.available() {
		return false
	}
	r, l := in.report(), in.Layout
	r.Warn("Restoring the previous release")
	_, _ = in.Host.Run(ctx, "systemctl", append([]string{"stop"}, units...)...)
	if copyFileAtomic(p.binary, l.Path(Binary), 0755) != nil || copyFileAtomic(p.engine, l.Path(Engine), 0700) != nil {
		r.Warn("Rollback failed; inspect systemctl status %s", units[len(units)-1])
		return false
	}
	if _, e := in.Host.Run(ctx, "systemctl", append([]string{"start"}, units...)...); e != nil {
		r.Warn("Rollback failed; inspect systemctl status %s", units[len(units)-1])
		return false
	}
	r.Done("Previous release restored and running")
	return true
}
