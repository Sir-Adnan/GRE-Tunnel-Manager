package gtm

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

const httpsUsage = `Usage
  gtm https                 Certificate status and choices
  gtm https status [--json] Current certificate and renewal
  gtm https issue [options] Trusted certificate from Let's Encrypt (domain or public IP)
      --domain NAME                  Default: the panel address
      --email ADDRESS                Optional contact
      --cloudflare-token-file FILE   Verify over Cloudflare DNS instead of port 80
      --staging                      Staging CA, for tests
  gtm https renew [--force]  Renew now when due (or always with --force)
  gtm https self-signed      Go back to a self-signed certificate
  gtm https install --cert FILE --key FILE   Use a certificate from Certbot or acme.sh`

func (a *App) https(ctx context.Context, args []string) error {
	sub := ""
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "help":
		return a.httpsHelp()
	case "":
		if len(args) > 0 && (args[0] == "--help" || args[0] == "-h") {
			return a.httpsHelp()
		}
		if len(args) > 0 {
			return errors.New("unknown option; run gtm https help")
		}
		if a.UI.Interactive || a.UI.Accessible {
			return a.httpsMenu(ctx)
		}
		return a.httpsStatus(ctx, nil)
	case "status":
		return a.httpsStatus(ctx, args)
	case "issue":
		return a.httpsIssue(ctx, args)
	case "renew", "install":
		return a.certificate(ctx, nil, append([]string{sub}, args...)...)
	case "self-signed":
		return a.certificate(ctx, nil, append([]string{sub, "--enable-https"}, args...)...)
	}
	return fmt.Errorf("unknown https command %q; run gtm https help", sub)
}

func (a *App) httpsHelp() error {
	a.UI.Header("gtm https", "", "Trusted certificates for the panel. Renewal never interrupts tunnels.")
	for _, line := range strings.Split(httpsUsage, "\n") {
		if line == "Usage" {
			a.UI.Section(line)
		} else {
			a.UI.Text("%s", line)
		}
	}
	a.UI.Blank()
	return nil
}

// certificate runs the installed certificate command with the operator's
// terminal attached. Secrets travel in env, never in arguments.
func (a *App) certificate(ctx context.Context, env []string, args ...string) error {
	if e := a.requireRoot(); e != nil {
		return e
	}
	return a.Installer.Host.StreamEnv(ctx, env, a.Installer.Layout.Path(install.Binary), append([]string{"certificate"}, args...)...)
}

func (a *App) httpsStatus(ctx context.Context, args []string) error {
	if len(args) == 1 && args[0] == "--json" {
		return a.certificate(ctx, nil, "status")
	}
	if len(args) != 0 {
		return errors.New("usage: gtm https status [--json]")
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	s := a.Installer.ReadStatus(ctx)
	if s.Certificate == nil {
		return errors.New("the panel is not installed or its configuration cannot be read")
	}
	a.UI.Header("Panel certificate", "", "")
	a.UI.Rows(certificateDetails(*s.Certificate, time.Now()))
	a.UI.Blank()
	return nil
}

func certificateDetails(c certificates.Status, now time.Time) []tui.Row {
	rows := []tui.Row{certificateRow(c, now), {Label: "Host", Value: c.Host}}
	if c.Protocol == "http" {
		return rows
	}
	if c.Issuer != "" {
		rows = append(rows, tui.Row{Label: "Issuer", Value: c.Issuer, Tone: tui.Quiet})
	}
	if !c.NotAfter.IsZero() {
		rows = append(rows, tui.Row{Label: "Expires", Value: c.NotAfter.Local().Format("2006-01-02 15:04") + " (" + days(c.NotAfter.Sub(now)) + ")", Tone: tui.Quiet})
	}
	if r := c.Renewal; r != nil && r.AutoRenew {
		rows = append(rows, tui.Row{Label: "Renews", Value: r.RenewAfter.Local().Format("2006-01-02") + " · checked every 6 hours", Tone: tui.Quiet})
		if r.LastError != "" {
			rows = append(rows, tui.Row{Label: "Last error", Value: r.LastError, Tone: tui.Bad})
		}
	}
	if c.Fingerprint != "" {
		rows = append(rows, tui.Row{Label: "SHA-256", Value: c.Fingerprint, Tone: tui.Quiet})
	}
	return rows
}

func (a *App) httpsMenu(ctx context.Context) error {
	if e := a.httpsStatus(ctx, nil); e != nil {
		return e
	}
	s := a.Installer.ReadStatus(ctx)
	managed := s.Certificate.Renewal != nil && s.Certificate.Renewal.AutoRenew
	choices := []tui.Choice[string]{{Label: "Get a trusted certificate from Let's Encrypt", Value: "issue"}}
	if managed {
		choices = []tui.Choice[string]{{Label: "Renew now", Value: "renew"}, {Label: "Issue again (new address or method)", Value: "issue"}}
	}
	choices = append(choices,
		tui.Choice[string]{Label: "Use a certificate from Certbot or acme.sh", Value: "external"},
		tui.Choice[string]{Label: "Switch to a self-signed certificate", Value: "self-signed"},
		tui.Choice[string]{Label: "Back", Value: "back"})
	choice := choices[0].Value
	if e := tui.Select(a.UI, "Certificate", "", choices, &choice); e != nil {
		return e
	}
	switch choice {
	case "issue":
		return a.httpsIssue(ctx, nil)
	case "renew":
		return a.certificate(ctx, nil, "renew", "--force")
	case "self-signed":
		proceed := false
		if e := a.UI.Confirm("Replace the current certificate with a self-signed one?", "Automatic renewal stops. Browsers will show a warning.", &proceed); e != nil || !proceed {
			return e
		}
		return a.certificate(ctx, nil, "self-signed", "--enable-https")
	case "external":
		a.UI.Section("Certificate from another ACME client")
		a.UI.Text("Point the client's deploy or renew hook at:")
		a.UI.Command("sudo gtm https install --cert /path/fullchain.pem --key /path/privkey.pem")
		a.UI.Hint("acme.sh supports 150+ DNS providers (for example --dns dns_hetzner). Automatic")
		a.UI.Hint("renewal inside the panel stops once an external certificate is installed.")
		a.UI.Hint("Guide: docs/HTTPS.md in the project repository.")
		a.UI.Blank()
	}
	return nil
}

func (a *App) httpsIssue(ctx context.Context, args []string) error {
	fs := a.flags("https issue", "Get a trusted Let's Encrypt certificate for the panel address (domain or public IP).")
	p := plan{}
	fs.StringVar(&p.setup.Host, "domain", "", "Domain or public IP (default: the panel address)")
	fs.StringVar(&p.setup.Host, "host", "", "alias of --domain")
	fs.StringVar(&p.email, "email", "", "Contact email (optional)")
	fs.StringVar(&p.tokenFile, "cloudflare-token-file", "", "Verify over Cloudflare DNS with the token in this file")
	fs.BoolVar(&p.staging, "staging", false, "Use the staging CA, for tests")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	c, e := config.Load(a.Installer.Layout.Path(install.ConfigFile))
	if e != nil {
		return e
	}
	asked := fs.NFlag() == 0 && (a.UI.Interactive || a.UI.Accessible)
	if p.setup.Host == "" {
		p.setup.Host = install.CertificateHost(c)
	}
	if asked {
		a.UI.Blank()
		if e = a.UI.Input("Certificate address", "The domain or public IP browsers use to open the panel.", "panel.example.com", &p.setup.Host, validHost); e != nil {
			return e
		}
		a.UI.Answer("Address", p.setup.Host)
		if e = a.wizardValidation(&p, net.ParseIP(p.setup.Host) != nil); e != nil {
			return e
		}
	}
	if p.tokenFile != "" && net.ParseIP(p.setup.Host) != nil {
		return errors.New("Cloudflare validation works for domains only; an IP address uses port 80")
	}
	certArgs, env := certificateRequest(p)
	certArgs = append([]string{"issue", "--enable-https", "--host", p.setup.Host}, certArgs...)
	a.UI.Step("Requesting a certificate for %s", p.setup.Host)
	if e = a.certificate(ctx, env, certArgs...); e != nil {
		return errors.New("no certificate was issued; the panel keeps its current one")
	}
	a.UI.Done("Trusted certificate installed for %s; it renews automatically", p.setup.Host)
	return nil
}
