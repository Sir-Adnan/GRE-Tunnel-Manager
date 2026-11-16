package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// Removal uses a closed manifest. Unknown files and links stop it for
// inspection; there is no recursive deletion and tunnels are never touched.

var tempWrite = regexp.MustCompile(`^\.(panel|tls)-[0-9]{1,10}$`)
var snapshotName = regexp.MustCompile(`^gtm-[0-9]{8}T[0-9]{6}\.json$`)
var leaseName = regexp.MustCompile(`^[a-f0-9]{32}\.json$`)

// panelDirectories are listed children-first so they can be removed in order.
var panelDirectories = []string{
	ConfigDir + "/acme", ConfigDir,
	StateDir + "/snapshots", StateDir,
	"/var/lib/gre-manager-nodes", "/var/lib/gre-manager-node-operations",
	UnitDir + "/gre-manager-panel.service.d",
}

var panelStateFiles = map[string]bool{
	"metrics.json": true, "health.json": true, "maintenance.json": true, "notifications.json": true,
	"snapshots.json": true, "prometheus.json": true, "optimize-watch.json": true, "ui-order.json": true,
	"safe-change.json": true, "update.json": true, "update-run.json": true, "audit.jsonl": true, "audit.jsonl.1": true,
}

var panelFixedFiles = map[string]bool{
	ConfigDir + "/acme/settings.json": true, ConfigDir + "/acme/account.key": true, ConfigDir + "/acme/cloudflare.token": true,
	ConfigDir + "/certificate.json": true, ConfigDir + "/config.json": true, ConfigDir + "/server.crt": true,
	ConfigDir + "/server.key": true, ConfigDir + "/https.pem": true, TwoFactorFile: true,
	"/var/lib/gre-manager-nodes/controller.json": true, "/var/lib/gre-manager-nodes/controller.lock": true,
	"/var/lib/gre-manager-nodes/pairs.json": true, "/var/lib/gre-manager-node-operations/broker.lock": true,
	UnitDir + "/gre-manager-panel.service.d/nodes.conf": true,
}

// ownedPanelFile reports a canonical path that removal may delete.
func ownedPanelFile(p string) bool {
	dir, name := filepath.Dir(p), filepath.Base(p)
	if tempWrite.MatchString(name) && (dir == ConfigDir || dir == StateDir || dir == ConfigDir+"/acme") {
		return strings.HasPrefix(name, ".panel-") || dir == ConfigDir
	}
	if panelFixedFiles[p] {
		return true
	}
	switch dir {
	case StateDir:
		return panelStateFiles[name]
	case StateDir + "/snapshots":
		return snapshotName.MatchString(name)
	case "/var/lib/gre-manager-node-operations":
		return leaseName.MatchString(name)
	}
	return false
}

func panelSubdirectory(p string) bool {
	return p == StateDir+"/snapshots" || p == ConfigDir+"/acme"
}

var panelUnitFiles = []string{PanelUnit, BrokerUnit, RenewalService, RenewalTimer, UpdateService, UpdateTimer}

// PanelInstalled reports any trace of a panel installation.
func (in *Installer) PanelInstalled() bool {
	l := in.Layout
	for _, p := range []string{Binary, ConfigDir, StateDir, "/var/lib/gre-manager-nodes", "/var/lib/gre-manager-node-operations"} {
		if l.exists(p) {
			return true
		}
	}
	return l.exists(UnitDir+"/"+PanelUnit) || l.exists(UnitDir+"/"+BrokerUnit)
}

// AgentInstalled reports any trace of an outbound Agent.
func (in *Installer) AgentInstalled() bool {
	l := in.Layout
	return l.exists("/var/lib/gre-manager-agent") || l.exists(UnitDir+"/"+AgentUnit) || l.exists(UnitDir+"/"+AgentBrokerUnit)
}

// checkPanelManifest refuses removal while anything unrecognized is present.
func (in *Installer) checkPanelManifest(ctx context.Context) error {
	l := in.Layout
	for _, dir := range panelDirectories {
		info, e := os.Lstat(l.Path(dir))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil || !info.IsDir() {
			return fmt.Errorf("unsafe panel directory: %s", dir)
		}
		entries, e := os.ReadDir(l.Path(dir))
		if e != nil {
			return e
		}
		for _, entry := range entries {
			p := dir + "/" + entry.Name()
			if panelSubdirectory(p) && entry.Type().IsDir() {
				continue
			}
			if !entry.Type().IsRegular() || !ownedPanelFile(p) {
				return fmt.Errorf("unrecognized panel file; inspect it before removal: %s", p)
			}
		}
	}
	for _, p := range append([]string{Binary, Engine}, unitPaths(panelUnitFiles)...) {
		if info, e := os.Lstat(l.Path(p)); e == nil && !info.Mode().IsRegular() {
			return fmt.Errorf("unsafe panel file: %s", p)
		}
	}
	for unit, exec := range map[string]string{PanelUnit: "ExecStart=/usr/local/bin/gtm-panel serve", BrokerUnit: "ExecStart=/usr/local/bin/gtm-panel broker"} {
		if data, e := os.ReadFile(l.Unit(unit)); e == nil {
			if !hasLine(string(data), exec) {
				return fmt.Errorf("customized service kept: %s", unit)
			}
		} else if _, e := in.Host.Run(ctx, "systemctl", "cat", unit); e == nil {
			return fmt.Errorf("service is outside the installer ownership path: %s", unit)
		}
	}
	return nil
}

func unitPaths(names []string) []string {
	out := make([]string, len(names))
	for i, n := range names {
		out[i] = UnitDir + "/" + n
	}
	return out
}

func hasLine(text, line string) bool {
	for _, l := range strings.Split(text, "\n") {
		if l == line {
			return true
		}
	}
	return false
}

// ErrNotInstalled means there is nothing to remove.
var ErrNotInstalled = errors.New("not installed")

// CheckPanelRemoval runs every refusal check without changing anything, so
// the caller can ask for confirmation only when removal can proceed.
func (in *Installer) CheckPanelRemoval(ctx context.Context) error {
	if _, e := in.Host.Run(ctx, "systemctl", "cat", AgentUnit); in.AgentInstalled() || e == nil {
		return errors.New("an Agent shares this host's files; remove it first with: sudo gtm agent remove")
	}
	if e := in.checkPanelManifest(ctx); e != nil {
		return e
	}
	if !in.PanelInstalled() {
		return ErrNotInstalled
	}
	if v, e := in.Host.Run(ctx, in.Layout.Path(Binary), "uninstall-version"); e != nil || v != "1" {
		return errors.New("update the installed panel to a release that supports safe removal first; nothing was stopped")
	}
	return nil
}

// RemovePanel removes the panel and keeps tunnels, forwards, engines and
// firewall policy. Call CheckPanelRemoval and confirm with the operator first.
func (in *Installer) RemovePanel(ctx context.Context) error {
	r, l, h := in.report(), in.Layout, in.Host
	lock, e := h.Lock(l.Path(LockFile))
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = in.CheckPanelRemoval(ctx); e != nil {
		return e
	}
	_, e1 := h.Run(ctx, "systemctl", "is-active", "--quiet", PanelUnit)
	_, e2 := h.Run(ctx, "systemctl", "is-active", "--quiet", BrokerUnit)
	wasActive, brokerActive := e1 == nil, e2 == nil
	restore := func() {
		if brokerActive {
			_, _ = h.Run(ctx, "systemctl", "start", BrokerUnit)
		}
		if wasActive {
			_, _ = h.Run(ctx, "systemctl", "start", PanelUnit)
		}
	}
	r.Step("Stopping the panel")
	if e = in.stopUnits(ctx, []string{PanelUnit, BrokerUnit}); e != nil {
		restore()
		return fmt.Errorf("service stop failed; files are kept and services restored: %w", e)
	}
	if _, e = h.Run(ctx, l.Path(Binary), "uninstall-prepare"); e != nil {
		restore()
		return fmt.Errorf("removal refused; files are kept and services restored: %w", e)
	}
	// Recheck after the services stopped; never delete files that appeared.
	if e = in.checkPanelManifest(ctx); e != nil {
		restore()
		return e
	}
	r.Step("Removing panel files")
	for _, unit := range []string{PanelUnit, BrokerUnit} {
		if regular(l.Unit(unit)) {
			if _, e = h.Run(ctx, "systemctl", "disable", unit); e != nil {
				return e
			}
		}
	}
	for _, timer := range []string{RenewalTimer, UpdateTimer} {
		if regular(l.Unit(timer)) {
			if _, e = h.Run(ctx, "systemctl", "disable", "--now", timer); e != nil {
				return e
			}
		}
	}
	for _, p := range unitPaths(panelUnitFiles) {
		if e = removeFile(l.Path(p)); e != nil {
			return e
		}
	}
	for _, dir := range panelDirectories {
		entries, e := os.ReadDir(l.Path(dir))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		for _, entry := range entries {
			p := dir + "/" + entry.Name()
			if panelSubdirectory(p) && entry.Type().IsDir() {
				continue
			}
			if !entry.Type().IsRegular() || !ownedPanelFile(p) {
				return fmt.Errorf("unrecognized panel file: %s", p)
			}
			if e = os.Remove(l.Path(p)); e != nil {
				return e
			}
		}
	}
	for _, dir := range panelDirectories {
		if e = os.Remove(l.Path(dir)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if _, e = h.Run(ctx, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	in.removeShared()
	r.Done("Web panel removed; tunnels and forwarding keep running")
	return nil
}

// removeShared deletes the executable, engine and shims once neither the
// panel nor an Agent needs them.
func (in *Installer) removeShared() {
	l := in.Layout
	if target, e := os.Readlink(l.Path(Command)); e == nil && (target == "gtm-panel" || target == Binary) {
		os.Remove(l.Path(Command))
	}
	if data, e := os.ReadFile(l.Path(Shortcut)); e == nil && string(data) == shortcutShim {
		os.Remove(l.Path(Shortcut))
	}
	_ = removeFile(l.Path(Engine))
	_ = removeFile(l.Path(Binary))
}

func removeFile(p string) error {
	if e := os.Remove(p); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}
