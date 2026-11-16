package gtm

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/issuer"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

// Connection security choices.
const (
	tlsLetsEncrypt = "letsencrypt"
	tlsSelfSigned  = "self-signed"
	tlsHTTP        = "http"
)

// plan is everything a fresh install needs, from flags or the wizard.
type plan struct {
	setup      install.Setup
	tls        string
	email      string
	tokenFile  string
	token      string // typed in the wizard; passed to the issuer by environment
	staging    bool
	generated  bool
	engines    bool
	agent      bool
	agentOpts  install.AgentOptions
	source     string
	noUpdates  bool
	assumeYes  bool
	setupFlags []string
}

func (a *App) installFlags(p *plan) (*flag.FlagSet, func() error) {
	fs := a.flags("install", "Install or repair the web panel. An existing panel keeps its address, port, login and certificates.")
	var https, selfSigned, http bool
	fs.StringVar(&p.setup.Host, "domain", "", "Domain or public IP for the panel (default: detected public IP)")
	fs.StringVar(&p.setup.Host, "address", "", "alias of --domain")
	fs.IntVar(&p.setup.Port, "port", 0, "TCP port (default: a free random port)")
	fs.StringVar(&p.setup.Username, "user", "admin", "Login name")
	fs.StringVar(&p.setup.Username, "username", "admin", "alias of --user")
	fs.StringVar(&p.setup.Password, "password", "", "Login password; visible in shell history, prefer --password-env")
	passwordEnv := fs.String("password-env", "", "Read the login password from this environment variable")
	fs.BoolVar(&https, "https", false, "Trusted HTTPS from Let's Encrypt (default)")
	fs.BoolVar(&selfSigned, "self-signed", false, "HTTPS with a self-signed certificate")
	fs.BoolVar(&http, "http", false, "Plain HTTP; login and traffic are not encrypted")
	fs.StringVar(&p.email, "email", "", "Contact email for Let's Encrypt (optional)")
	fs.StringVar(&p.tokenFile, "cloudflare-token-file", "", "Verify the domain over Cloudflare DNS with the API token in this file")
	fs.BoolVar(&p.staging, "staging", false, "Use the Let's Encrypt staging CA, for tests")
	fs.StringVar(&p.setup.Listen, "listen", "", "Local IP to listen on (default: every address)")
	fs.BoolVar(&p.engines, "engines", false, "Also install every tunnel engine")
	fs.BoolVar(&p.engines, "install-engines", false, "alias of --engines")
	fs.BoolVar(&p.noUpdates, "no-update-check", false, "Do not check GitHub daily for a newer release")
	fs.BoolVar(&p.assumeYes, "yes", false, "Accept defaults and ask nothing")
	fs.BoolVar(&p.assumeYes, "y", false, "alias of --yes")
	fs.StringVar(&p.source, "source", "", "Unpacked release directory (set by install.sh and gtm update)")
	fs.BoolVar(&p.agent, "agent", false, "Install an outbound Agent instead of the panel")
	fs.BoolVar(&p.agentOpts.Operations, "operations", false, "Agent: allow leased GRE/FRP creation")
	fs.BoolVar(&p.agentOpts.Traffic, "traffic", false, "Agent: allow read-only traffic summaries")
	finish := func() error {
		modes := 0
		for _, on := range []struct {
			set  bool
			mode string
		}{{https, tlsLetsEncrypt}, {selfSigned, tlsSelfSigned}, {http, tlsHTTP}} {
			if on.set {
				modes++
				p.tls = on.mode
			}
		}
		if modes > 1 {
			return errors.New("choose one of --https, --self-signed or --http")
		}
		if *passwordEnv != "" {
			if p.setup.Password != "" {
				return errors.New("use --password or --password-env, not both")
			}
			secret, e := a.secretFromEnv(*passwordEnv)
			if e != nil {
				return e
			}
			p.setup.Password = secret
		}
		return nil
	}
	return fs, finish
}

func (a *App) install(ctx context.Context, args []string) error {
	p := plan{}
	fs, finish := a.installFlags(&p)
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return fmt.Errorf("unexpected argument %q (see gtm install --help)", fs.Arg(0))
	}
	if e := finish(); e != nil {
		return e
	}
	fs.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "domain", "address", "port", "user", "username", "password", "password-env", "https", "self-signed", "http", "email", "cloudflare-token-file", "staging", "listen":
			p.setupFlags = append(p.setupFlags, "--"+f.Name)
		}
	})
	if e := validatePlan(&p); e != nil {
		return e
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	pkg, e := a.sourcePackage(p.source)
	if e != nil {
		return e
	}
	if p.agent {
		return a.installAgent(ctx, pkg, p.agentOpts)
	}
	fresh := !regularFile(a.Installer.Layout.Path(install.ConfigFile))
	if fresh {
		if e = a.preparePlan(ctx, &p); e != nil {
			return e
		}
	} else {
		a.UI.Header("GRE Tunnel Manager", "v"+a.Version, "Updating the web panel")
		if len(p.setupFlags) > 0 {
			a.UI.Warn("Ignored %s: the existing panel keeps its settings", strings.Join(p.setupFlags, ", "))
			a.UI.Note("Change them with gtm https, gtm port and gtm password")
		}
	}
	a.UI.Blank()
	options := install.PanelOptions{Source: pkg, Setup: p.setup, Engines: p.engines}
	if p.noUpdates {
		off := false
		options.UpdateCheck = &off
	}
	if fresh && p.tls == tlsLetsEncrypt {
		options.Certificate, options.CertificateEnv = certificateRequest(p)
	}
	result, e := a.Installer.InstallPanel(ctx, options)
	if e != nil {
		return e
	}
	a.panelSummary(ctx, result, p, fresh)
	return nil
}

func validatePlan(p *plan) error {
	s := &p.setup
	if s.Host != "" && !config.ValidHost(s.Host) {
		return errors.New("--domain must be a domain or IP address, without a scheme, path or port")
	}
	if s.Port < 0 || s.Port > 65535 {
		return errors.New("--port must be 1–65535")
	}
	if !config.UserPattern.MatchString(s.Username) {
		return errors.New("--user must be 3–40 ASCII letters, digits, dots, dashes or underscores")
	}
	if s.Listen != "" && net.ParseIP(s.Listen) == nil {
		return errors.New("--listen must be a local IP address")
	}
	if s.Password != "" {
		if e := config.ValidatePassword(s.Password); e != nil {
			return e
		}
	}
	acme := p.email != "" || p.tokenFile != "" || p.staging
	if acme && (p.tls == tlsHTTP || p.tls == tlsSelfSigned) {
		return errors.New("--email, --staging and --cloudflare-token-file need Let's Encrypt; drop --http or --self-signed")
	}
	if p.email != "" && !issuer.ValidEmail(p.email) {
		return errors.New("--email is not a valid address")
	}
	if p.tokenFile != "" {
		if net.ParseIP(s.Host) != nil {
			return errors.New("Cloudflare validation works for domains only; an IP address uses port 80")
		}
		if !regularFile(p.tokenFile) {
			return errors.New("--cloudflare-token-file must be a readable regular file")
		}
	}
	if p.agent && len(p.setupFlags) > 0 {
		return errors.New("panel options cannot be combined with --agent")
	}
	return nil
}

// preparePlan fills the remaining choices: from the wizard on a terminal,
// otherwise from defaults (Let's Encrypt, random port, generated password).
func (a *App) preparePlan(ctx context.Context, p *plan) error {
	if !p.assumeYes && (a.UI.Interactive || a.UI.Accessible) {
		return a.wizard(ctx, p)
	}
	a.UI.Header("GRE Tunnel Manager", "v"+a.Version, "Installing the web panel")
	if p.setup.Host == "" {
		a.UI.Step("Detecting this server's public IP")
		host, e := a.Discover(ctx)
		if e != nil {
			return errors.New("public IP detection failed; pass --domain with a domain or the server's IP")
		}
		p.setup.Host = host
	}
	if p.tls == "" {
		p.tls = tlsLetsEncrypt
	}
	return a.finishPlan(p)
}

func (a *App) finishPlan(p *plan) error {
	p.setup.Protocol = "https"
	if p.tls == tlsHTTP {
		p.setup.Protocol = "http"
	}
	if p.setup.Password == "" {
		secret, e := generatePassword()
		if e != nil {
			return e
		}
		p.setup.Password, p.generated = secret, true
	}
	return nil
}

func (a *App) wizard(ctx context.Context, p *plan) error {
	u := a.UI
	u.Header("GRE Tunnel Manager", "v"+a.Version, "Web panel setup · Esc cancels at any step")
	u.Blank()
	if p.setup.Host == "" {
		u.Step("Detecting this server's public IP")
		if host, e := a.Discover(ctx); e == nil {
			p.setup.Host = host
		}
	}
	if !hasFlag(p, "--domain", "--address") {
		if e := u.Input("Panel address", "A domain that points to this server, or its public IP. Both can get a trusted certificate.", "panel.example.com", &p.setup.Host, validHost); e != nil {
			return e
		}
	}
	u.Answer("Address", p.setup.Host)
	isIP := net.ParseIP(p.setup.Host) != nil
	if p.tls == "" {
		p.tls = tlsLetsEncrypt
		le := "HTTPS · Let's Encrypt  trusted, renews automatically"
		if isIP {
			le = "HTTPS · Let's Encrypt  trusted IP certificate, renewed every few days"
		}
		if e := tui.Select(u, "Connection security", "", []tui.Choice[string]{
			{Label: le, Value: tlsLetsEncrypt},
			{Label: "HTTPS · self-signed    encrypted, browsers show a warning", Value: tlsSelfSigned},
			{Label: "HTTP                   not encrypted; only for private networks", Value: tlsHTTP},
		}, &p.tls); e != nil {
			return e
		}
	}
	u.Answer("Security", map[string]string{tlsLetsEncrypt: "HTTPS · Let's Encrypt", tlsSelfSigned: "HTTPS · self-signed", tlsHTTP: "HTTP"}[p.tls])
	if p.tls == tlsLetsEncrypt {
		if e := a.wizardValidation(p, isIP); e != nil {
			return e
		}
	}
	if !hasFlag(p, "--port") {
		text := ""
		if e := u.Input("Panel port", "Leave empty for a random free port. Avoid 80 and 443 if other services use them.", "random", &text, validPortText); e != nil {
			return e
		}
		p.setup.Port, _ = strconv.Atoi(strings.TrimSpace(text))
	}
	u.Answer("Port", portLabel(p.setup.Port))
	if !hasFlag(p, "--user", "--username") {
		if e := u.Input("Login name", "", "admin", &p.setup.Username, validUser); e != nil {
			return e
		}
	}
	u.Answer("Login", p.setup.Username)
	if p.setup.Password == "" {
		mode := "generate"
		if e := tui.Select(u, "Login password", "", []tui.Choice[string]{
			{Label: "Generate a strong password  shown once at the end", Value: "generate"},
			{Label: "Choose my own", Value: "own"},
		}, &mode); e != nil {
			return e
		}
		if mode == "own" {
			if e := u.Secret("Password", &p.setup.Password, config.ValidatePassword); e != nil {
				return e
			}
		}
	}
	if !p.engines {
		if e := u.Confirm("Install every tunnel engine now?", "iptables, nftables, HAProxy, Realm, FRP and rathole. You can also add them later in the panel.", &p.engines); e != nil {
			return e
		}
	}
	u.Answer("Engines", map[bool]string{true: "all", false: "later, from the panel"}[p.engines])
	if e := a.finishPlan(p); e != nil {
		return e
	}
	proceed := true
	if e := u.Confirm("Install now?", "Only panel services are created; existing tunnels and firewall rules are not changed.", &proceed); e != nil {
		return e
	}
	if !proceed {
		return tui.ErrCancelled
	}
	return nil
}

func (a *App) wizardValidation(p *plan, isIP bool) error {
	u := a.UI
	if !isIP && p.tokenFile == "" {
		method := "http-01"
		if e := tui.Select(u, "How should Let's Encrypt verify the domain?", "", []tui.Choice[string]{
			{Label: "Port 80        opened for a few seconds; simplest", Value: "http-01"},
			{Label: "Cloudflare DNS no open port; needs an API token with Zone.DNS edit", Value: "cloudflare"},
		}, &method); e != nil {
			return e
		}
		if method == "cloudflare" {
			if e := u.Hidden("Cloudflare API token", "Stored root-only on this server for renewals. Never shown again.", &p.token, validToken); e != nil {
				return e
			}
		}
	}
	verify := "port 80"
	if p.token != "" || p.tokenFile != "" {
		verify = "Cloudflare DNS"
	}
	u.Answer("Verification", verify)
	if p.email == "" {
		if e := u.Input("Email for certificate notices", "Optional. Let's Encrypt uses it only for account notices.", "you@example.com", &p.email, validOptionalEmail); e != nil {
			return e
		}
	}
	if p.email != "" {
		u.Answer("Email", p.email)
	}
	return nil
}

// certificateRequest builds "certificate issue" arguments. A typed token
// travels in the environment, never in argv.
func certificateRequest(p plan) (args, env []string) {
	args = []string{}
	if p.email != "" {
		args = append(args, "--email", p.email)
	}
	if p.tokenFile != "" {
		args = append(args, "--challenge", "cloudflare", "--cloudflare-token-file", p.tokenFile)
	} else if p.token != "" {
		args = append(args, "--challenge", "cloudflare")
		env = []string{"CLOUDFLARE_API_TOKEN=" + p.token}
	}
	if p.staging {
		args = append(args, "--staging")
	}
	return args, env
}

func (a *App) panelSummary(ctx context.Context, r install.PanelResult, p plan, fresh bool) {
	u, c := a.UI, r.Config
	_, port, _ := net.SplitHostPort(c.Listen)
	security := tui.Row{Label: "HTTPS"}
	switch {
	case c.Scheme() == "http":
		security.Value, security.Tone = "Off · traffic is not encrypted", tui.Warning
	case p.tls == tlsLetsEncrypt && fresh && r.CertificateError == nil:
		security.Value, security.Tone = "Let's Encrypt · renews automatically", tui.Good
	case p.tls == tlsLetsEncrypt && fresh:
		security.Value, security.Tone = "Self-signed for now · retry: sudo gtm https issue", tui.Warning
	case fresh:
		security.Value, security.Tone = "Self-signed · browsers show a warning", tui.Warning
	default:
		// An update keeps the certificate; show what is actually loaded.
		if s := a.Installer.ReadStatus(ctx); s.Certificate != nil {
			security = certificateRow(*s.Certificate, time.Now())
		} else {
			security.Value = "unchanged"
		}
	}
	rows := []tui.Row{{Label: "Address", Value: c.URL()}, {Label: "Login", Value: c.Username}}
	if p.generated && fresh {
		rows = append(rows, tui.Row{Label: "Password", Value: p.setup.Password})
	}
	rows = append(rows, security)
	var notes []string
	if p.generated && fresh {
		notes = append(notes, "Save the password now; it is not shown again.")
	}
	if fresh && r.Fingerprint != "" && (p.tls == tlsSelfSigned || r.CertificateError != nil) {
		rows = append(rows, tui.Row{Label: "SHA-256", Value: r.Fingerprint, Tone: tui.Quiet})
		notes = append(notes, "Compare this fingerprint over SSH before signing in.")
	}
	notes = append(notes, "Allow TCP "+port+" in the server and provider firewall.", "Manage later with: sudo gtm")
	title := "Panel ready"
	if !fresh {
		title = "Panel updated to v" + a.Version
	}
	u.Card(title, rows, notes...)
	u.Blank()
}

// sourcePackage picks the release to install: an unpacked directory from
// install.sh or gtm update, or the files already installed (repair).
func (a *App) sourcePackage(dir string) (release.Package, error) {
	if dir != "" {
		return release.Local(dir)
	}
	if p, ok := a.Installer.InstalledPackage(); ok {
		return p, nil
	}
	return release.Package{}, errors.New("no release package: run the installer from https://github.com/" + release.Repository)
}

func hasFlag(p *plan, names ...string) bool {
	for _, set := range p.setupFlags {
		for _, n := range names {
			if set == n {
				return true
			}
		}
	}
	return false
}

func portLabel(port int) string {
	if port == 0 {
		return "random free port"
	}
	return strconv.Itoa(port)
}

func regularFile(path string) bool {
	info, e := os.Stat(path)
	return e == nil && info.Mode().IsRegular()
}

func validHost(s string) error {
	if !config.ValidHost(strings.TrimSpace(s)) {
		return errors.New("enter a domain such as panel.example.com or an IP address")
	}
	return nil
}

func validPortText(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	if n, e := strconv.Atoi(s); e != nil || n < 1 || n > 65535 {
		return errors.New("enter a port from 1 to 65535, or leave it empty")
	}
	return nil
}

func validUser(s string) error {
	if !config.UserPattern.MatchString(s) {
		return errors.New("3–40 letters, digits, dots, dashes or underscores")
	}
	return nil
}

func validOptionalEmail(s string) error {
	if s != "" && !issuer.ValidEmail(s) {
		return errors.New("enter a valid address or leave it empty")
	}
	return nil
}

func validToken(s string) error {
	if !issuer.ValidToken(strings.TrimSpace(s)) {
		return errors.New("this does not look like a Cloudflare API token")
	}
	return nil
}
