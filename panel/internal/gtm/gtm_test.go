package gtm

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install/installtest"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

type fixture struct {
	t    *testing.T
	app  *App
	host *installtest.Host
	out  *bytes.Buffer
	env  map[string]string
	pkg  string
}

func newFixture(t *testing.T) *fixture {
	root := t.TempDir()
	for _, d := range []string{"usr/local/bin", "etc/systemd/system", "run"} {
		os.MkdirAll(filepath.Join(root, d), 0755)
	}
	pkg := t.TempDir()
	os.WriteFile(filepath.Join(pkg, "gtm-panel"), []byte("binary"), 0755)
	os.WriteFile(filepath.Join(pkg, "gre.sh"), []byte("engine"), 0700)
	out := &bytes.Buffer{}
	ui := tui.Plain(strings.NewReader(""), out)
	host := installtest.New()
	f := &fixture{t: t, host: host, out: out, env: map[string]string{}, pkg: pkg}
	f.app = &App{
		UI: ui,
		Installer: &install.Installer{Host: host, Layout: install.Layout{Root: root}, Report: ui,
			Wait: time.Nanosecond, Dial: func(context.Context, string) error { return nil }},
		Version:  "1.6.0",
		Root:     true,
		Getenv:   func(k string) string { return f.env[k] },
		Discover: func(context.Context) (string, error) { return "203.0.113.20", nil },
	}
	return f
}

func (f *fixture) run(args ...string) error {
	f.t.Helper()
	return f.app.Main(context.Background(), args)
}

func (f *fixture) config() config.Config {
	f.t.Helper()
	c, e := config.Load(f.app.Installer.Layout.Path(install.ConfigFile))
	if e != nil {
		f.t.Fatal(e)
	}
	return c
}

func TestInstallWithoutTerminalUsesDefaults(t *testing.T) {
	f := newFixture(t)
	if e := f.run("install", "--source", f.pkg); e != nil {
		t.Fatalf("%v\n%s", e, f.out)
	}
	c := f.config()
	if c.PublicHost != "203.0.113.20" || c.Username != "admin" || c.Scheme() != "https" {
		t.Fatalf("config %+v", c)
	}
	f.host.Index(t, f.app.Installer.Layout.Path(install.Binary)+" certificate issue --enable-https")
	out := f.out.String()
	for _, want := range []string{"Panel ready", "Password", "Let's Encrypt · renews automatically", "sudo gtm"} {
		if !strings.Contains(out, want) {
			t.Fatalf("summary lacks %q:\n%s", want, out)
		}
	}
}

func TestInstallRejectsBadOptionsBeforeAnyChange(t *testing.T) {
	for _, args := range [][]string{
		{"--http", "--email", "ops@example.com"},
		{"--https", "--self-signed"},
		{"--password", "long enough secret", "--password-env", "GTM_PW"},
		{"--password-env", "UNSET"},
		{"--port", "70000"},
		{"--domain", "https://example.com"},
		{"--agent", "--domain", "panel.example.com"},
		{"--domain", "203.0.113.5", "--cloudflare-token-file", "/etc/hostname"},
		{"--password", "short"},
		{"extra"},
	} {
		f := newFixture(t)
		if e := f.run(append([]string{"install", "--source", f.pkg}, args...)...); e == nil {
			t.Errorf("%v accepted", args)
		}
		if len(f.host.Calls) != 0 {
			t.Errorf("%v ran commands: %s", args, f.host.Log())
		}
		if strings.Contains(f.out.String(), "long enough secret") {
			t.Errorf("%v echoed a secret", args)
		}
	}
}

func TestPasswordFromEnvironmentStaysOutOfArguments(t *testing.T) {
	f := newFixture(t)
	f.env["GTM_PW"] = "environment secret 42"
	if e := f.run("install", "--source", f.pkg, "--self-signed", "--password-env", "GTM_PW", "--user", "ops"); e != nil {
		t.Fatal(e)
	}
	if strings.Contains(f.host.Log(), "environment secret") || strings.Contains(f.out.String(), "environment secret") {
		t.Fatal("password leaked into commands or output")
	}
	if strings.Contains(f.host.Log(), "certificate issue") {
		t.Fatal("self-signed install ordered a certificate")
	}
	if c := f.config(); c.Username != "ops" {
		t.Fatalf("user %s", c.Username)
	}
}

func TestExistingPanelKeepsSettings(t *testing.T) {
	f := newFixture(t)
	if e := f.run("install", "--source", f.pkg, "--self-signed"); e != nil {
		t.Fatal(e)
	}
	before := f.config()
	f.out.Reset()
	if e := f.run("install", "--source", f.pkg, "--port", "1234", "--http"); e != nil {
		t.Fatal(e)
	}
	if after := f.config(); after != before {
		t.Fatal("update changed settings")
	}
	if !strings.Contains(f.out.String(), "Ignored --http, --port") || !strings.Contains(f.out.String(), "Panel updated") {
		t.Fatalf("output:\n%s", f.out)
	}
}

func TestTypedCloudflareTokenTravelsInEnvironment(t *testing.T) {
	token := strings.Repeat("a", 40)
	args, env := certificateRequest(plan{token: token, email: "ops@example.com"})
	if strings.Contains(strings.Join(args, " "), token) || len(env) != 1 || env[0] != "CLOUDFLARE_API_TOKEN="+token {
		t.Fatalf("args %v env %v", args, env)
	}
	if strings.Join(args, " ") != "--email ops@example.com --challenge cloudflare" {
		t.Fatalf("args %v", args)
	}
}

func TestRemoveNeedsConfirmationWithoutTerminal(t *testing.T) {
	f := newFixture(t)
	if e := f.run("install", "--source", f.pkg, "--self-signed"); e != nil {
		t.Fatal(e)
	}
	if e := f.run("remove"); e == nil || !strings.Contains(e.Error(), "--yes") {
		t.Fatalf("removed without confirmation: %v", e)
	}
	if e := f.run("remove", "--yes"); e != nil {
		t.Fatal(e)
	}
	if f.app.Installer.PanelInstalled() {
		t.Fatal("panel still installed")
	}
	f.out.Reset()
	if e := f.run("remove", "--yes"); e != nil || !strings.Contains(f.out.String(), "not installed") {
		t.Fatalf("second removal: %v %s", e, f.out)
	}
}

func releaseServer(t *testing.T, version string) *httptest.Server {
	name := release.ArchiveName(version, "amd64")
	if a, _ := release.Arch(); a == "arm64" {
		name = release.ArchiveName(version, "arm64")
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for n, body := range map[string]string{"gtm-panel": "next", "gre.sh": "engine"} {
		tw.WriteHeader(&tar.Header{Name: n, Mode: 0755, Size: int64(len(body)), Typeflag: tar.TypeReg})
		tw.Write([]byte(body))
	}
	tw.Close()
	gz.Close()
	data := buf.Bytes()
	sum := sha256.Sum256(data)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasSuffix(r.URL.Path, "/releases/latest"):
			w.Write([]byte(`{"tag_name":"v` + version + `"}`))
		case strings.HasSuffix(r.URL.Path, "/"+name):
			w.Write(data)
		case strings.HasSuffix(r.URL.Path, "/SHA256SUMS"):
			w.Write([]byte(hex.EncodeToString(sum[:]) + "  " + name + "\n"))
		default:
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestUpdateCheckAndInstall(t *testing.T) {
	f := newFixture(t)
	if e := f.run("install", "--source", f.pkg, "--self-signed"); e != nil {
		t.Fatal(e)
	}
	server := releaseServer(t, "1.6.1")
	f.app.Release = release.Client{HTTP: server.Client(), API: server.URL + "/api", Download: server.URL + "/dl"}
	f.out.Reset()
	if e := f.run("update", "--check"); e != nil {
		t.Fatal(e)
	}
	if !strings.Contains(f.out.String(), "v1.6.1 is available") {
		t.Fatalf("output:\n%s", f.out)
	}
	check, e := release.LoadCheck(f.app.Installer.Layout.Path(release.CheckPath))
	if e != nil || check.Latest != "1.6.1" || !check.Available() {
		t.Fatalf("record %+v %v", check, e)
	}
	f.host.Answer = func(line string) (string, error, bool) {
		if strings.HasSuffix(line, "/gtm-panel version") {
			return "v1.6.1", nil, true
		}
		return "", nil, false
	}
	if e := f.run("update", "--yes"); e != nil {
		t.Fatalf("%v\n%s", e, f.out)
	}
	last := f.host.Calls[len(f.host.Calls)-1]
	if !strings.Contains(last, "/gtm-panel gtm install --source ") || !strings.HasSuffix(last, " --yes") {
		t.Fatalf("new release not handed over: %s", last)
	}
	f.app.Version = "1.6.1"
	f.out.Reset()
	if e := f.run("update"); e != nil || !strings.Contains(f.out.String(), "Already on v1.6.1") {
		t.Fatalf("%v %s", e, f.out)
	}
}

func TestUpdateRefusesMismatchedPackage(t *testing.T) {
	f := newFixture(t)
	if e := f.run("install", "--source", f.pkg, "--self-signed"); e != nil {
		t.Fatal(e)
	}
	server := releaseServer(t, "1.6.1")
	f.app.Release = release.Client{HTTP: server.Client(), API: server.URL + "/api", Download: server.URL + "/dl"}
	f.host.Answer = func(line string) (string, error, bool) {
		if strings.HasSuffix(line, "/gtm-panel version") {
			return "v1.5.0", nil, true
		}
		return "", nil, false
	}
	if e := f.run("update", "--yes"); e == nil || !strings.Contains(e.Error(), "different version") {
		t.Fatalf("mismatch accepted: %v", e)
	}
	// The panel's one-click update reads how the run ended.
	if e := f.run("update", "--yes", "--record"); e == nil {
		t.Fatal("mismatch accepted")
	}
	run, e := release.LoadRun(f.app.Installer.Layout.Path(release.RunPath))
	if e != nil || run.State != release.RunFailed || run.From != "1.6.0" || run.To != "1.6.1" || !strings.Contains(run.Error, "different version") || run.Finished.IsZero() {
		t.Fatalf("record %+v %v", run, e)
	}
	f.host.Answer = func(line string) (string, error, bool) {
		if strings.HasSuffix(line, "/gtm-panel version") {
			return "v1.6.1", nil, true
		}
		return "", nil, false
	}
	if e := f.run("update", "--yes", "--record"); e != nil {
		t.Fatal(e)
	}
	if run, _ = release.LoadRun(f.app.Installer.Layout.Path(release.RunPath)); run.State != release.RunSucceeded || run.To != "1.6.1" {
		t.Fatalf("record %+v", run)
	}
	// The panel asked for a release that is not newer: nothing to do is a
	// failure, never a success that changed nothing.
	if e := f.run("update", "--yes", "--record", "--version", "1.6.0"); e == nil || !strings.Contains(e.Error(), "not newer") {
		t.Fatal(e)
	}
	if run, _ = release.LoadRun(f.app.Installer.Layout.Path(release.RunPath)); run.State != release.RunFailed {
		t.Fatalf("record %+v", run)
	}
}

func TestTwoFactorOff(t *testing.T) {
	f := newFixture(t)
	if e := f.run("install", "--source", f.pkg, "--self-signed"); e != nil {
		t.Fatal(e)
	}
	f.out.Reset()
	if e := f.run("2fa", "off"); e != nil || !strings.Contains(f.out.String(), "already off") {
		t.Fatalf("%v %s", e, f.out)
	}
	path := f.app.Installer.Layout.Path(install.TwoFactorFile)
	if e := os.WriteFile(path, []byte("{}"), 0640); e != nil {
		t.Fatal(e)
	}
	if e := f.run("2fa", "off", "--yes"); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(path); !os.IsNotExist(e) {
		t.Fatal("settings kept")
	}
	if f.host.Index(t, "systemctl try-restart gre-manager-panel.service") < 0 {
		t.Fatal("panel not restarted")
	}
	if e := f.run("2fa", "on"); e == nil {
		t.Fatal("turning it on is done in the panel")
	}
}

func TestPasswordCommand(t *testing.T) {
	f := newFixture(t)
	if e := f.run("install", "--source", f.pkg, "--self-signed"); e != nil {
		t.Fatal(e)
	}
	before := f.config().PasswordHash
	if e := f.run("password"); e == nil {
		t.Fatal("no terminal and no option accepted")
	}
	f.out.Reset()
	if e := f.run("password", "--generate", "--user", "operator"); e != nil {
		t.Fatal(e)
	}
	c := f.config()
	if c.PasswordHash == before || c.Username != "operator" || !strings.Contains(f.out.String(), "Login updated") {
		t.Fatalf("not updated:\n%s", f.out)
	}
}

func TestStatusRowsAndMenu(t *testing.T) {
	now := time.Date(2026, 11, 16, 12, 0, 0, 0, time.UTC)
	s := install.Status{Panel: true, PanelState: "active", BrokerState: "active", URL: "https://panel.example.com:2053", Username: "admin",
		Certificate: &certificates.Status{Protocol: "https", NotAfter: now.Add(80 * 24 * time.Hour),
			Renewal: &certificates.Renewal{AutoRenew: true, RenewAfter: now.Add(50*24*time.Hour + time.Hour)}},
		Update: release.Check{Latest: "1.6.1"}}
	a := &App{Version: "1.6.0"}
	var text []string
	for _, r := range a.statusRows(s, now) {
		text = append(text, r.Label+"="+r.Value)
	}
	joined := strings.Join(text, "|")
	for _, want := range []string{"Panel=active", "HTTPS=Let's Encrypt · renews in 51 days", "Update=v1.6.1 available · gtm update"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("rows lack %q: %s", want, joined)
		}
	}
	if strings.Contains(joined, "Broker") {
		t.Fatal("healthy broker shown")
	}
	menu := menuFor(s, "1.6.0")
	if menu[0].Value != "update" || menu[len(menu)-1].Value != "quit" {
		t.Fatalf("menu %+v", menu)
	}
	for v := range menuCommands {
		if _, ok := a.commands()[menuCommands[v][0]]; !ok {
			t.Fatalf("menu item %s runs an unknown command", v)
		}
	}
}

func TestHelpUnknownAndRoot(t *testing.T) {
	f := newFixture(t)
	if e := f.run("bogus"); e == nil {
		t.Fatal("unknown command accepted")
	}
	if e := f.run("install", "--help"); e != nil || !strings.Contains(f.out.String(), "--domain VALUE") {
		t.Fatalf("install help: %v\n%s", e, f.out)
	}
	f.app.Root = false
	if e := f.run("status"); e == nil || !strings.Contains(e.Error(), "sudo") {
		t.Fatalf("non-root status: %v", e)
	}
}
