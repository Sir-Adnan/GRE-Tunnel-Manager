package install

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
)

// Installer performs panel and Agent lifecycle work on one host.
type Installer struct {
	Host   Host
	Layout Layout
	Report Reporter
	// Wait bounds the post-start health check (default 20s).
	Wait time.Duration
	// Dial probes the panel listener (default: a plain TCP connect).
	Dial func(ctx context.Context, address string) error
	// Interfaces lists local addresses for a self-signed certificate.
	Interfaces func() []string
}

// Setup describes a fresh panel. It is ignored when a configuration exists.
type Setup struct {
	Host     string // public IP or domain
	Listen   string // local IP; empty picks the IPv4 or IPv6 wildcard
	Port     int    // 0 picks a free random port
	Username string
	Password string
	Protocol string // https or http
}

// PanelOptions selects what one install or update does.
type PanelOptions struct {
	Source  release.Package
	Setup   Setup
	Engines bool
	// Certificate, when set, requests a Let's Encrypt certificate after the
	// panel is running: extra "certificate issue" arguments and environment.
	Certificate    []string
	CertificateEnv []string
	// UpdateCheck nil keeps the current choice (on for a new install).
	UpdateCheck *bool
}

// PanelResult describes what happened, for the summary screen.
type PanelResult struct {
	Fresh       bool
	Config      config.Config
	Fingerprint string
	// CertificateError is a failed Let's Encrypt order; the install stands.
	CertificateError error
}

// Engines installed by --engines, in the order the engine expects.
var Engines = []string{"iptables", "nftables", "haproxy", "realm", "frp", "rathole"}

func (in *Installer) report() Reporter {
	if in.Report == nil {
		return Quiet{}
	}
	return in.Report
}

// InstallPanel installs, updates or repairs the panel. Nothing that serves
// users is stopped until the new package and the configuration are proven.
func (in *Installer) InstallPanel(ctx context.Context, o PanelOptions) (PanelResult, error) {
	r, l, h := in.report(), in.Layout, in.Host
	var result PanelResult
	if e := in.checkPackage(ctx, o.Source); e != nil {
		return result, e
	}
	if e := in.ensureTools(ctx); e != nil {
		return result, e
	}
	lock, e := h.Lock(l.Path(LockFile))
	if e != nil {
		return result, e
	}
	locked := true
	defer func() {
		if locked {
			lock.Close()
		}
	}()
	account, e := ensureAccount(ctx, h, "grepanel")
	if e != nil {
		return result, e
	}
	r.Done("Service account grepanel is ready")
	for _, d := range []struct {
		path     string
		mode     os.FileMode
		uid, gid int
	}{{LibDir, 0755, 0, 0}, {ConfigDir, 0750, 0, account.GID}, {StateDir, 0700, 0, 0}} {
		if e = ensureDir(h, l.Path(d.path), d.mode, d.uid, d.gid); e != nil {
			return result, e
		}
	}
	configPath := l.Path(ConfigFile)
	if _, statErr := os.Lstat(configPath); errors.Is(statErr, os.ErrNotExist) {
		r.Step("Creating the panel configuration")
		cfg, fingerprint, e := in.createConfig(configPath, o.Setup)
		if e != nil {
			return result, e
		}
		result.Fresh, result.Fingerprint = true, fingerprint
		r.Done("Panel configured for %s", cfg.URL())
	} else {
		r.Note("Existing address, port, login and certificates are kept")
	}
	// Validate the configuration with the incoming release before any stop.
	cfg, e := config.Load(configPath)
	if e != nil {
		return result, fmt.Errorf("the panel configuration is not valid; nothing was stopped: %w", e)
	}
	result.Config = cfg
	if e = in.securePanelFiles(configPath, cfg, account); e != nil {
		return result, e
	}
	previous, e := in.snapshot()
	if e != nil {
		return result, e
	}
	defer previous.discard()
	if e = in.deploy(ctx, o.Source, []string{BrokerUnit, PanelUnit}); e != nil {
		in.rollback(ctx, previous, []string{BrokerUnit, PanelUnit})
		return result, e
	}
	// Read the operator's choice before the unit files are (re)written: a
	// timer that did not exist yet is new, not disabled.
	updateCheck := o.UpdateCheck
	if updateCheck == nil {
		on := !in.timerDisabled(ctx, UpdateTimer)
		updateCheck = &on
	}
	in.installShims()
	for _, u := range panelUnits {
		if e = writeUnit(l, u.name, u.body); e != nil {
			return result, e
		}
	}
	steps := [][]string{{"daemon-reload"}, {"enable", "--now", RenewalTimer}}
	if *updateCheck {
		steps = append(steps, []string{"enable", "--now", UpdateTimer})
	} else {
		steps = append(steps, []string{"disable", "--now", UpdateTimer})
	}
	steps = append(steps, []string{"enable", "--now", BrokerUnit, PanelUnit})
	r.Step("Starting the panel")
	for _, args := range steps {
		if _, e = h.Run(ctx, "systemctl", args...); e != nil {
			break
		}
	}
	if e == nil {
		e = in.waitHealthy(ctx, cfg)
	}
	if e != nil {
		_ = h.Stream(ctx, "journalctl", "-u", PanelUnit, "-n", "20", "--no-pager")
		if in.rollback(ctx, previous, []string{BrokerUnit, PanelUnit}) {
			return result, fmt.Errorf("the new release did not start; the previous release was restored: %w", e)
		}
		return result, fmt.Errorf("the panel did not start: %w", e)
	}
	r.Done("Panel is running")
	if o.Engines {
		r.Step("Installing tunnel engines")
		args := append([]string{l.Path(Engine), "--api", "install"}, Engines...)
		if e = h.Stream(ctx, "/bin/bash", args...); e != nil {
			r.Warn("Engine installation failed; install them later under Tunnel engines in the panel")
		} else {
			r.Done("Tunnel engines installed")
		}
	}
	if o.Certificate != nil {
		// The certificate command takes the installer lock itself.
		lock.Close()
		locked = false
		r.Step("Requesting a trusted certificate from Let's Encrypt")
		args := append([]string{"certificate", "issue", "--enable-https"}, o.Certificate...)
		if e = h.StreamEnv(ctx, o.CertificateEnv, l.Path(Binary), args...); e != nil {
			result.CertificateError = e
			r.Warn("The panel keeps its current certificate; fix the cause above and run: sudo gtm https issue")
		} else {
			r.Done("Trusted certificate installed; it renews automatically")
		}
		if reloaded, e := config.Load(configPath); e == nil {
			result.Config = reloaded
		}
	}
	return result, nil
}

func (in *Installer) checkPackage(ctx context.Context, p release.Package) error {
	if !regular(p.Binary) || !regular(p.Engine) {
		return errors.New("the release package is incomplete")
	}
	if _, e := in.Host.Run(ctx, "bash", "-n", p.Engine); e != nil {
		return fmt.Errorf("the engine script in the package is damaged: %w", e)
	}
	return nil
}

func (in *Installer) ensureTools(ctx context.Context) error {
	for _, tool := range []string{"systemctl", "apt-get"} {
		if in.Host.LookPath(tool) != nil {
			return errors.New("Debian or Ubuntu with systemd is required")
		}
	}
	if in.Host.LookPath("ip") == nil {
		return nil
	}
	in.report().Step("Installing iproute2")
	if e := in.Host.Stream(ctx, "apt-get", "update"); e != nil {
		return e
	}
	return in.Host.Stream(ctx, "apt-get", "install", "-y", "--no-install-recommends", "iproute2", "ca-certificates")
}

func (in *Installer) createConfig(path string, s Setup) (config.Config, string, error) {
	listen := s.Listen
	if listen == "" {
		listen = "0.0.0.0"
		if ip := net.ParseIP(s.Host); ip != nil && ip.To4() == nil {
			listen = "::"
		}
	}
	var addresses []string
	if in.Interfaces != nil {
		addresses = in.Interfaces()
	}
	return config.Create(path, config.Options{Listen: listen, Port: s.Port, Username: s.Username, Password: s.Password, Protocol: s.Protocol, PublicHost: s.Host, Addresses: addresses})
}

// securePanelFiles keeps the configuration and the self-signed key readable
// by the panel account only.
func (in *Installer) securePanelFiles(configPath string, c config.Config, a Account) error {
	files := []string{configPath}
	dir := filepath.Dir(configPath)
	for _, name := range []string{"server.key", "server.crt"} {
		if regular(filepath.Join(dir, name)) {
			files = append(files, filepath.Join(dir, name))
		}
	}
	for _, f := range files {
		if e := in.Host.Chown(f, 0, a.GID); e != nil {
			return e
		}
		if e := os.Chmod(f, 0640); e != nil {
			return e
		}
	}
	return nil
}

// timerDisabled reports a timer the operator turned off on purpose.
func (in *Installer) timerDisabled(ctx context.Context, name string) bool {
	if !regular(in.Layout.Unit(name)) {
		return false
	}
	state, _ := in.Host.Run(ctx, "systemctl", "is-enabled", name)
	return state == "disabled"
}

func (in *Installer) waitHealthy(ctx context.Context, c config.Config) error {
	wait := in.Wait
	if wait == 0 {
		wait = 20 * time.Second
	}
	dial := in.Dial
	if dial == nil {
		dial = func(ctx context.Context, address string) error {
			conn, e := (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", address)
			if e == nil {
				conn.Close()
			}
			return e
		}
	}
	address := probeAddress(c.Listen)
	deadline := time.Now().Add(wait)
	for {
		_, active := in.Host.Run(ctx, "systemctl", "is-active", "--quiet", PanelUnit)
		var e error
		if active == nil {
			if e = dial(ctx, address); e == nil {
				return nil
			}
		} else {
			e = errors.New("the service is not active")
		}
		if time.Now().After(deadline) {
			return e
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// probeAddress turns a wildcard listener into a loopback address to dial.
func probeAddress(listen string) string {
	host, port, e := net.SplitHostPort(listen)
	if e != nil {
		return listen
	}
	switch host {
	case "0.0.0.0", "":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return net.JoinHostPort(host, port)
}

const shortcutShim = `#!/bin/sh
# igre is kept for compatibility. Tunnels are managed in the web panel;
# gtm installs, updates and maintains it.
exec /usr/local/bin/gtm "$@"
`

// installShims links the gtm command and retires an old igre menu copy.
// Files the installer does not recognize are left alone.
func (in *Installer) installShims() {
	l, r := in.Layout, in.report()
	command := l.Path(Command)
	if target, e := os.Readlink(command); e == nil {
		if target != "gtm-panel" && target != Binary {
			r.Warn("%s points elsewhere and was kept; use gtm-panel gtm instead", Command)
		}
	} else if _, e := os.Lstat(command); errors.Is(e, os.ErrNotExist) {
		if e = os.Symlink("gtm-panel", command); e != nil {
			r.Warn("Could not create %s: %v", Command, e)
		}
	} else {
		r.Warn("%s already exists and was kept; use gtm-panel gtm instead", Command)
	}
	if ownsShortcut(l.Path(Shortcut)) {
		if e := writeFileAtomic(l.Path(Shortcut), []byte(shortcutShim), 0755); e != nil {
			r.Warn("Could not update %s: %v", Shortcut, e)
		}
	}
}

// ownsShortcut recognizes the shim and the copies of gre.sh that releases
// before v1.6.0 installed as igre.
func ownsShortcut(path string) bool {
	if !regular(path) {
		return false
	}
	data, e := os.ReadFile(path)
	if e != nil || len(data) > 8<<20 {
		return false
	}
	text := string(data)
	return text == shortcutShim || strings.Contains(text, `SHORTCUT_NAME="igre"`) || strings.Contains(text, "GTM_SHORTCUT_PATH=/usr/local/bin/igre")
}

// LocalAddresses lists this host's interface addresses for a self-signed
// certificate's alternative names.
func LocalAddresses() []string {
	var out []string
	values, e := net.InterfaceAddrs()
	if e != nil {
		return nil
	}
	for _, value := range values {
		if ip, _, e := net.ParseCIDR(value.String()); e == nil {
			out = append(out, ip.String())
		}
	}
	return out
}

// InstalledPackage describes the release already on this host, used to
// repair units and files without downloading anything.
func (in *Installer) InstalledPackage() (release.Package, bool) {
	p := release.Package{Dir: in.Layout.Path(LibDir), Binary: in.Layout.Path(Binary), Engine: in.Layout.Path(Engine)}
	return p, regular(p.Binary) && regular(p.Engine)
}
