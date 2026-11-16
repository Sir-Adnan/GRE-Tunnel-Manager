package install

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install/installtest"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
)

type harness struct {
	t    *testing.T
	root string
	host *installtest.Host
	in   *Installer
	pkg  release.Package
}

func newHarness(t *testing.T) *harness {
	root := t.TempDir()
	for _, d := range []string{"usr/local/bin", "etc/systemd/system", "run", "pkg"} {
		if e := os.MkdirAll(filepath.Join(root, d), 0755); e != nil {
			t.Fatal(e)
		}
	}
	pkg := release.Package{Dir: filepath.Join(root, "pkg"), Binary: filepath.Join(root, "pkg/gtm-panel"), Engine: filepath.Join(root, "pkg/gre.sh")}
	writeFile(t, pkg.Binary, "new-binary")
	writeFile(t, pkg.Engine, "new-engine")
	h := installtest.New()
	return &harness{t: t, root: root, host: h, pkg: pkg, in: &Installer{
		Host: h, Layout: Layout{Root: root}, Wait: time.Nanosecond,
		Dial: func(context.Context, string) error { return nil },
	}}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(path), 0755); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(path, []byte(body), 0644); e != nil {
		t.Fatal(e)
	}
}

func (h *harness) path(p string) string { return h.in.Layout.Path(p) }

func (h *harness) read(p string) string {
	data, e := os.ReadFile(h.path(p))
	if e != nil {
		h.t.Fatal(e)
	}
	return string(data)
}

func (h *harness) freshInstall(o PanelOptions) PanelResult {
	h.t.Helper()
	if o.Source.Binary == "" {
		o.Source = h.pkg
	}
	if o.Setup.Username == "" {
		o.Setup = Setup{Host: "203.0.113.10", Username: "admin", Password: "correct horse battery", Protocol: "https"}
	}
	r, e := h.in.InstallPanel(context.Background(), o)
	if e != nil {
		h.t.Fatalf("install: %v\n%s", e, h.host.Log())
	}
	return r
}

func TestFreshInstallWritesUnitsLinksAndStartsServices(t *testing.T) {
	h := newHarness(t)
	r := h.freshInstall(PanelOptions{})
	if !r.Fresh || r.Fingerprint == "" || !strings.HasPrefix(r.Config.URL(), "https://203.0.113.10:") {
		t.Fatalf("result %+v", r)
	}
	if h.read(Binary) != "new-binary" || h.read(Engine) != "new-engine" {
		t.Fatal("release files were not installed")
	}
	if target, e := os.Readlink(h.path(Command)); e != nil || target != "gtm-panel" {
		t.Fatalf("gtm link: %q %v", target, e)
	}
	for _, u := range panelUnits {
		if h.read(UnitDir+"/"+u.name) != u.body {
			t.Fatalf("unit %s differs", u.name)
		}
	}
	if !strings.Contains(h.read(UnitDir+"/"+UpdateService), "ExecStart=/usr/local/bin/gtm-panel update-check") {
		t.Fatal("update check runs the canonical binary")
	}
	log := h.host.Log()
	if strings.Contains(log, "systemctl stop") || strings.Contains(log, "certificate issue") {
		t.Fatalf("fresh install stopped services or ordered a certificate:\n%s", log)
	}
	if h.host.Index(t, "systemctl enable --now "+UpdateTimer) > h.host.Index(t, "systemctl enable --now "+BrokerUnit) {
		t.Fatal("timers are enabled before the panel starts")
	}
	if info, _ := os.Stat(h.path(ConfigFile)); info.Mode().Perm() != 0640 {
		t.Fatalf("config mode %v", info.Mode())
	}
}

func TestUpdateKeepsConfigurationAndCertificates(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	before := h.read(ConfigFile)
	writeFile(t, h.path(ConfigDir+"/server.key"), "operator-key")
	writeFile(t, h.pkg.Binary, "newer-binary")
	h.host.Calls = nil
	r, e := h.in.InstallPanel(context.Background(), PanelOptions{Source: h.pkg, Setup: Setup{Host: "198.51.100.1", Username: "other", Password: "another password", Protocol: "http"}})
	if e != nil {
		t.Fatal(e)
	}
	if r.Fresh || h.read(ConfigFile) != before || h.read(ConfigDir+"/server.key") != "operator-key" {
		t.Fatal("update changed the configuration or certificate")
	}
	if h.read(Binary) != "newer-binary" {
		t.Fatal("binary not updated")
	}
	h.host.Index(t, "systemctl stop "+BrokerUnit+" "+PanelUnit)
}

func TestBrokenConfigurationStopsNothing(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	writeFile(t, h.path(ConfigFile), "broken")
	h.host.Calls = nil
	if _, e := h.in.InstallPanel(context.Background(), PanelOptions{Source: h.pkg}); e == nil {
		t.Fatal("broken configuration accepted")
	}
	if strings.Contains(h.host.Log(), "systemctl stop") || h.read(ConfigFile) != "broken" {
		t.Fatal("a broken configuration must not stop or change anything")
	}
}

func TestDamagedPackageChangesNothing(t *testing.T) {
	h := newHarness(t)
	h.host.Fail["bash -n"] = errors.New("syntax error")
	if _, e := h.in.InstallPanel(context.Background(), PanelOptions{Source: h.pkg, Setup: Setup{Host: "203.0.113.10", Username: "admin", Password: "correct horse battery", Protocol: "https"}}); e == nil {
		t.Fatal("damaged engine accepted")
	}
	if regular(h.path(ConfigFile)) || len(h.host.Calls) != 1 {
		t.Fatalf("damaged package changed the host:\n%s", h.host.Log())
	}
}

func TestFailedStartRestoresPreviousRelease(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	writeFile(t, h.pkg.Binary, "broken-binary")
	h.host.Fail["systemctl is-active --quiet "+PanelUnit] = errors.New("failed")
	_, e := h.in.InstallPanel(context.Background(), PanelOptions{Source: h.pkg})
	if e == nil || !strings.Contains(e.Error(), "previous release was restored") {
		t.Fatalf("error %v", e)
	}
	if h.read(Binary) != "new-binary" {
		t.Fatal("previous binary not restored")
	}
	h.host.Index(t, "systemctl start "+BrokerUnit+" "+PanelUnit)
	h.host.Index(t, "journalctl -u "+PanelUnit)
}

func TestLetsEncryptRunsAfterStartAndFailureKeepsInstall(t *testing.T) {
	h := newHarness(t)
	h.host.Fail[h.path(Binary)+" certificate issue"] = errors.New("connection refused")
	r := h.freshInstall(PanelOptions{Certificate: []string{"--email", "ops@example.com"}})
	if r.CertificateError == nil {
		t.Fatal("certificate failure not reported")
	}
	issue := h.host.Index(t, h.path(Binary)+" certificate issue --enable-https --email ops@example.com")
	if issue < h.host.Index(t, "systemctl enable --now "+BrokerUnit) {
		t.Fatal("certificate requested before the panel runs")
	}
}

func TestUpdateCheckChoiceIsKept(t *testing.T) {
	h := newHarness(t)
	off := false
	h.freshInstall(PanelOptions{UpdateCheck: &off})
	h.host.Index(t, "systemctl disable --now "+UpdateTimer)
	h.host.Calls = nil
	h.host.Out["systemctl is-enabled "+UpdateTimer] = "disabled"
	if _, e := h.in.InstallPanel(context.Background(), PanelOptions{Source: h.pkg}); e != nil {
		t.Fatal(e)
	}
	h.host.Index(t, "systemctl disable --now "+UpdateTimer)
}

// Upgrading a release that had no update timer must turn it on, even though
// systemd reports a just-written, never-enabled unit as "disabled".
func TestUpgradeFromReleaseWithoutUpdateTimerEnablesIt(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	os.Remove(h.in.Layout.Unit(UpdateTimer))
	os.Remove(h.in.Layout.Unit(UpdateService))
	h.host.Out["systemctl is-enabled "+UpdateTimer] = "disabled"
	h.host.Calls = nil
	if _, e := h.in.InstallPanel(context.Background(), PanelOptions{Source: h.pkg}); e != nil {
		t.Fatal(e)
	}
	h.host.Index(t, "systemctl enable --now "+UpdateTimer)
}

func TestShortcutShimReplacesOnlyOldCopies(t *testing.T) {
	h := newHarness(t)
	writeFile(t, h.path(Shortcut), "#!/bin/bash\nSHORTCUT_NAME=\"igre\"\nmenu\n")
	h.freshInstall(PanelOptions{})
	if h.read(Shortcut) != shortcutShim {
		t.Fatal("old igre copy not replaced")
	}
	h2 := newHarness(t)
	writeFile(t, h2.path(Shortcut), "my own script")
	writeFile(t, h2.path(Command), "someone else's gtm")
	h2.freshInstall(PanelOptions{})
	if h2.read(Shortcut) != "my own script" || h2.read(Command) != "someone else's gtm" {
		t.Fatal("unrelated files were replaced")
	}
}

func TestRemovalRefusesUnknownFilesLinksAndAgents(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	ctx := context.Background()
	unknown := h.path(ConfigDir + "/notes.txt")
	writeFile(t, unknown, "keep")
	if e := h.in.CheckPanelRemoval(ctx); e == nil || !strings.Contains(e.Error(), "notes.txt") {
		t.Fatalf("unknown file accepted: %v", e)
	}
	os.Remove(unknown)
	link := h.path(StateDir + "/metrics.json")
	if e := os.Symlink("/etc/passwd", link); e != nil {
		t.Fatal(e)
	}
	if h.in.CheckPanelRemoval(ctx) == nil {
		t.Fatal("symbolic link accepted")
	}
	os.Remove(link)
	os.MkdirAll(h.path("/var/lib/gre-manager-agent"), 0700)
	if e := h.in.CheckPanelRemoval(ctx); e == nil || !strings.Contains(e.Error(), "Agent") {
		t.Fatalf("Agent not detected: %v", e)
	}
	os.Remove(h.path("/var/lib/gre-manager-agent"))
	h.host.Out[h.path(Binary)+" uninstall-version"] = "0"
	if h.in.CheckPanelRemoval(ctx) == nil {
		t.Fatal("old binary accepted")
	}
	if strings.Contains(h.host.Log(), "systemctl stop") {
		t.Fatal("checks must not stop services")
	}
}

func TestRemovalDeletesOwnedFilesAndKeepsTunnels(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	tunnel := h.path("/etc/gre-manager/state.tsv")
	writeFile(t, tunnel, "keep tunnels")
	writeFile(t, h.path(StateDir+"/snapshots/gtm-20260101T010203.json"), "{}")
	writeFile(t, h.path(StateDir+"/update.json"), "{}")
	writeFile(t, h.path(ConfigDir+"/acme/account.key"), "key")
	writeFile(t, h.path(ConfigDir+"/.panel-123"), "partial")
	h.host.Calls = nil
	if e := h.in.RemovePanel(context.Background()); e != nil {
		t.Fatalf("%v\n%s", e, h.host.Log())
	}
	for _, p := range []string{ConfigDir, StateDir, Binary, Engine, Command, UnitDir + "/" + PanelUnit, UnitDir + "/" + UpdateTimer} {
		if _, e := os.Lstat(h.path(p)); !errors.Is(e, os.ErrNotExist) {
			t.Fatalf("%s still exists", p)
		}
	}
	if h.read("/etc/gre-manager/state.tsv") != "keep tunnels" {
		t.Fatal("tunnel state touched")
	}
	if h.host.Index(t, h.path(Binary)+" uninstall-prepare") < h.host.Index(t, "systemctl stop") {
		t.Fatal("prepared before stopping")
	}
	if e := h.in.CheckPanelRemoval(context.Background()); !errors.Is(e, ErrNotInstalled) {
		t.Fatalf("after removal: %v", e)
	}
}

func TestRefusedRemovalRestartsServicesAndKeepsFiles(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	h.host.Fail[h.path(Binary)+" uninstall-prepare"] = errors.New("refused")
	if h.in.RemovePanel(context.Background()) == nil {
		t.Fatal("refusal ignored")
	}
	if !regular(h.path(ConfigFile)) || !regular(h.path(Binary)) {
		t.Fatal("files removed after refusal")
	}
	h.host.Index(t, "systemctl start "+PanelUnit)
	if strings.Contains(h.host.Log(), "systemctl disable") {
		t.Fatal("units disabled after refusal")
	}
}

func TestCustomizedServiceIsKept(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	writeFile(t, h.in.Layout.Unit(PanelUnit), "[Service]\nExecStart=/opt/custom serve\n")
	if e := h.in.CheckPanelRemoval(context.Background()); e == nil || !strings.Contains(e.Error(), "customized") {
		t.Fatalf("customized unit accepted: %v", e)
	}
}

func TestChangePortAndCredentials(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	ctx := context.Background()
	c, e := h.in.ChangePort(ctx, 46123)
	if e != nil {
		t.Fatal(e)
	}
	if !strings.HasSuffix(c.Listen, ":46123") {
		t.Fatalf("listen %s", c.Listen)
	}
	saved, _ := config.Load(h.path(ConfigFile))
	if saved.Listen != c.Listen {
		t.Fatal("port not saved")
	}
	h.host.Index(t, "systemctl restart "+PanelUnit)
	if _, e = h.in.ChangePort(ctx, 46123); e == nil {
		t.Fatal("same port accepted")
	}
	old := saved.PasswordHash
	if _, e = h.in.SetCredentials(ctx, "operator", "a new long password"); e != nil {
		t.Fatal(e)
	}
	saved, _ = config.Load(h.path(ConfigFile))
	if saved.PasswordHash == old || saved.Username != "operator" {
		t.Fatal("credentials not saved")
	}
	if _, e = h.in.SetCredentials(ctx, "", "short"); e == nil {
		t.Fatal("weak password accepted")
	}
}

func TestFailedPortChangeIsReverted(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	before, _ := config.Load(h.path(ConfigFile))
	h.host.Fail["systemctl is-active --quiet "+PanelUnit] = errors.New("failed")
	if _, e := h.in.ChangePort(context.Background(), 46124); e == nil || !strings.Contains(e.Error(), "reverted") {
		t.Fatalf("error %v", e)
	}
	after, _ := config.Load(h.path(ConfigFile))
	if after.Listen != before.Listen {
		t.Fatal("port not restored")
	}
}

func TestAgentInstallKeepsIdentityAndOptIns(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	o, e := h.in.InstallAgent(ctx, h.pkg, AgentOptions{Operations: true})
	if e != nil {
		t.Fatalf("%v\n%s", e, h.host.Log())
	}
	h.host.Index(t, "runuser -u greagent -- "+h.pkg.Binary+" nodes enroll")
	if !strings.Contains(h.read(UnitDir+"/"+AgentUnit), "ExecStart=/usr/local/bin/gtm-panel nodes agent --operations\n") ||
		!strings.Contains(h.read(UnitDir+"/"+AgentBrokerUnit), "--read-only --node-operations --socket") || !o.Operations {
		t.Fatal("operations opt-in missing from units")
	}
	writeFile(t, h.path(agentDir+"/identity.json"), "{}")
	h.host.Calls = nil
	o, e = h.in.InstallAgent(ctx, h.pkg, AgentOptions{Traffic: true})
	if e != nil {
		t.Fatal(e)
	}
	if !o.Operations || !o.Traffic || strings.Contains(h.host.Log(), "nodes enroll") {
		t.Fatalf("upgrade lost an opt-in or enrolled again: %+v\n%s", o, h.host.Log())
	}
	if !strings.Contains(h.read(UnitDir+"/"+AgentUnit), "nodes agent --operations --traffic\n") {
		t.Fatal("traffic opt-in missing")
	}
}

func TestAgentRefusesPanelHostAndBadIdentity(t *testing.T) {
	h := newHarness(t)
	h.freshInstall(PanelOptions{})
	if _, e := h.in.InstallAgent(context.Background(), h.pkg, AgentOptions{}); e == nil || !strings.Contains(e.Error(), "local Node") {
		t.Fatalf("panel host accepted: %v", e)
	}
	h2 := newHarness(t)
	h2.host.Fail["runuser -u greagent -- "+h2.pkg.Binary+" nodes check"] = errors.New("bad identity")
	if _, e := h2.in.InstallAgent(context.Background(), h2.pkg, AgentOptions{}); e == nil {
		t.Fatal("bad identity accepted")
	}
	if strings.Contains(h2.host.Log(), "systemctl stop") || regular(h2.path(Binary)) {
		t.Fatal("bad identity changed services or files")
	}
}

func TestAgentRemovalWaitsForPendingOperations(t *testing.T) {
	h := newHarness(t)
	ctx := context.Background()
	if _, e := h.in.InstallAgent(ctx, h.pkg, AgentOptions{Operations: true}); e != nil {
		t.Fatal(e)
	}
	writeFile(t, h.path(agentDir+"/identity.json"), "{}")
	lease := h.path(operationsDir + "/0123456789abcdef0123456789abcdef.json")
	writeFile(t, lease, "{}")
	if e := h.in.RemoveAgent(ctx); e == nil || !strings.Contains(e.Error(), "pending") {
		t.Fatalf("pending lease ignored: %v", e)
	}
	os.Remove(lease)
	if e := h.in.RemoveAgent(ctx); e != nil {
		t.Fatal(e)
	}
	for _, p := range []string{agentDir, UnitDir + "/" + AgentUnit, Binary, Command} {
		if _, e := os.Lstat(h.path(p)); !errors.Is(e, os.ErrNotExist) {
			t.Fatalf("%s still exists", p)
		}
	}
}

func TestOwnedPanelFileManifest(t *testing.T) {
	for p, want := range map[string]bool{
		ConfigDir + "/.tls-12":                   true,
		StateDir + "/.tls-12":                    false,
		ConfigDir + "/acme/.panel-9":             true,
		StateDir + "/update.json":                true,
		StateDir + "/snapshots/gtm-x.json":       false,
		StateDir + "/other.json":                 false,
		"/var/lib/gre-manager-node-operations/x": false,
	} {
		if ownedPanelFile(p) != want {
			t.Errorf("%s: want %v", p, want)
		}
	}
}
