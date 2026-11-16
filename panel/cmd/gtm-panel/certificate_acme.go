package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/issuer"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/version"
)

// One order normally takes seconds; the cap covers DNS propagation waits.
const orderTimeout = 6 * time.Minute

// CloudflareTokenEnv is read when --cloudflare-token-file is not given, so the
// token never appears in arguments, shell history or process listings.
const CloudflareTokenEnv = "CLOUDFLARE_API_TOKEN"

func certificateIssue(ctx context.Context, args []string) error {
	fs, path := certificateFlags("issue")
	host := fs.String("host", "", "domain or public IP to certify (default: the panel's public address)")
	email := fs.String("email", "", "optional contact address for the ACME account")
	challenge := fs.String("challenge", issuer.ChallengeHTTP, "http-01 (port 80) or cloudflare (DNS, domains only)")
	tokenFile := fs.String("cloudflare-token-file", "", "file holding a Cloudflare API token (or set "+CloudflareTokenEnv+")")
	staging := fs.Bool("staging", false, "use the Let's Encrypt staging CA (untrusted certificates, for testing)")
	directory := fs.String("directory", "", "another ACME directory URL (advanced)")
	profile := fs.String("profile", "", "ACME profile; default is shortlived for IP addresses")
	httpAddress := fs.String("http-address", "", "listener for http-01 validation (default :80)")
	enableHTTPS := fs.Bool("enable-https", false, "switch an HTTP panel to HTTPS (restarts only the public panel)")
	if e := parseOnly(fs, args); e != nil {
		return e
	}
	lease, e := lockAsRoot()
	if e != nil {
		return e
	}
	defer lease.Close()
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	if *host == "" {
		*host = certificateHost(c)
	}
	if e = publicIdentifier(*host); e != nil {
		return e
	}
	settings := issuer.Settings{Version: 1, Host: strings.ToLower(*host), Email: *email, Directory: issuer.LetsEncrypt, Challenge: *challenge, Profile: *profile, HTTPAddress: *httpAddress}
	if *staging {
		settings.Directory = issuer.LetsEncryptStaging
	}
	if *directory != "" {
		settings.Directory = *directory
	}
	if e = settings.Validate(); e != nil {
		return e
	}
	token := ""
	if settings.Challenge == issuer.ChallengeCloudflare {
		if token, e = cloudflareToken(*tokenFile); e != nil {
			return e
		}
	}
	store := storeFor(*path)
	status, renewal, e := obtainAndApply(ctx, store, settings, token, change{configPath: *path, host: settings.Host, enableHTTPS: *enableHTTPS, reload: true})
	if e != nil {
		return e
	}
	if e = store.SaveSettings(settings); e == nil && token != "" {
		e = store.SaveToken(token)
	}
	if e != nil {
		return fmt.Errorf("certificate installed, but automatic renewal could not be saved: %w", e)
	}
	saveRecord(store, renewal)
	fmt.Printf("Trusted certificate installed for %s, valid until %s.\nAutomatic renewal starts after %s.\n", status.Host, status.NotAfter.UTC().Format(time.RFC3339), renewal.RenewAfter.UTC().Format(time.RFC3339))
	if settings.Directory == issuer.LetsEncryptStaging {
		fmt.Println("Staging certificates are not trusted by browsers; issue again without --staging for production.")
	}
	return nil
}

func certificateRenew(ctx context.Context, args []string) error {
	fs, path := certificateFlags("renew")
	force := fs.Bool("force", false, "renew now even if the certificate is not due")
	if e := parseOnly(fs, args); e != nil {
		return e
	}
	store := storeFor(*path)
	settings, managed, e := store.Settings()
	if e != nil {
		return e
	}
	if !managed {
		fmt.Println("Automatic renewal is not configured; nothing to do.")
		return nil
	}
	lease, e := lockAsRoot()
	if e != nil {
		// The timer runs again in a few hours; an install in progress is not a failure.
		fmt.Println("Skipped: another panel installation or certificate change is running.")
		return nil
	}
	defer lease.Close()
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	if current := certificateHost(c); !strings.EqualFold(current, settings.Host) {
		return fmt.Errorf("the panel address changed from %s to %s; run gtm-panel certificate issue for the new address", settings.Host, current)
	}
	previous, _ := store.Record()
	if !*force {
		if renewAfter, ok := currentRenewAfter(c); ok && time.Now().Before(renewAfter) {
			fmt.Printf("Certificate is not due; renewal starts after %s.\n", renewAfter.UTC().Format(time.RFC3339))
			return nil
		}
	}
	token := ""
	if settings.Challenge == issuer.ChallengeCloudflare {
		if token, e = store.Token(); e != nil {
			return e
		}
	}
	status, renewal, e := obtainAndApply(ctx, store, settings, token, change{configPath: *path, reload: true})
	if e != nil {
		previous.Version, previous.Source, previous.Host, previous.AutoRenew = 1, settings.Source(), settings.Host, true
		previous.LastAttempt, previous.LastError = time.Now().UTC(), e.Error()
		saveRecord(store, previous)
		return e
	}
	saveRecord(store, renewal)
	fmt.Printf("Certificate renewed for %s, valid until %s.\n", status.Host, status.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

func certificateSelfSigned(ctx context.Context, args []string) error {
	fs, path := certificateFlags("self-signed")
	host := fs.String("host", "", "public IP or domain to include (default: the panel's public address)")
	enableHTTPS := fs.Bool("enable-https", false, "switch an HTTP panel to HTTPS (restarts only the public panel)")
	if e := parseOnly(fs, args); e != nil {
		return e
	}
	lease, e := lockAsRoot()
	if e != nil {
		return e
	}
	defer lease.Close()
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	if *host == "" {
		*host = certificateHost(c)
	}
	addresses := []string{*host}
	if values, e := net.InterfaceAddrs(); e == nil {
		for _, value := range values {
			if ip, _, e := net.ParseCIDR(value.String()); e == nil {
				addresses = append(addresses, ip.String())
			}
		}
	}
	certPEM, keyPEM, fingerprint, e := config.SelfSigned(addresses)
	if e != nil {
		return e
	}
	status, e := applyCertificate(ctx, change{configPath: *path, host: *host, enableHTTPS: *enableHTTPS, reload: true, certPEM: certPEM, keyPEM: keyPEM})
	if e != nil {
		return e
	}
	store := storeFor(*path)
	if e = store.Disable(); e != nil {
		return e
	}
	saveRecord(store, certificates.Renewal{Source: certificates.SourceSelfSigned, Host: status.Host, NotAfter: status.NotAfter})
	fmt.Printf("Self-signed certificate installed for %s, valid until %s.\nSHA-256: %s\nBrowsers will warn; compare this fingerprint before accepting it.\n", status.Host, status.NotAfter.UTC().Format(time.RFC3339), fingerprint)
	return nil
}

// obtainAndApply runs one ACME order and installs the result. The loaded
// certificate is replaced only after the new one validates for the host.
func obtainAndApply(ctx context.Context, store issuer.Store, settings issuer.Settings, token string, ch change) (certificates.Status, certificates.Renewal, error) {
	var renewal certificates.Renewal
	key, e := store.AccountKey()
	if e != nil {
		return certificates.Status{}, renewal, e
	}
	var solver issuer.Solver = issuer.HTTP01{Address: settings.HTTPAddress}
	if settings.Challenge == issuer.ChallengeCloudflare {
		solver = issuer.Cloudflare{Token: token}
	}
	order, cancel := context.WithTimeout(ctx, orderTimeout)
	defer cancel()
	result, e := issuer.Obtain(order, issuer.Request{
		Directory: settings.Directory, Host: settings.Host, Email: settings.Email, Profile: settings.Profile,
		AccountKey: key, Solver: solver, UserAgent: "gtm-panel/" + version.Number,
		Log: func(format string, args ...any) { fmt.Printf(format+"\n", args...) },
	})
	if e != nil {
		return certificates.Status{}, renewal, withHint(settings, e)
	}
	ch.certPEM, ch.keyPEM = result.CertificatePEM, result.KeyPEM
	status, e := applyCertificate(ctx, ch)
	if e != nil {
		return status, renewal, e
	}
	renewal = certificates.Renewal{
		Source: settings.Source(), Host: status.Host, Challenge: settings.Challenge, Profile: result.Profile,
		Staging: settings.Directory == issuer.LetsEncryptStaging, AutoRenew: true,
		Issued: status.NotBefore, NotAfter: status.NotAfter, RenewAfter: certificates.RenewAfter(status.NotBefore, status.NotAfter),
		LastAttempt: time.Now().UTC(),
	}
	return status, renewal, nil
}

// withHint adds the one next step that fixes most failed validations.
func withHint(settings issuer.Settings, e error) error {
	if settings.Challenge == issuer.ChallengeHTTP {
		return fmt.Errorf("%w\nCheck that TCP port 80 on %s reaches this server: allow it in the server and provider firewall, and make sure no forward or relay uses port 80. Nothing was changed", e, settings.Host)
	}
	return fmt.Errorf("%w\nCheck the Cloudflare token permissions (Zone → Read, DNS → Edit) for the zone of %s. Nothing was changed", e, settings.Host)
}

// currentRenewAfter reads the installed certificate's lifetime; anything
// unreadable or invalid is due immediately.
func currentRenewAfter(c config.Config) (time.Time, bool) {
	if c.Scheme() != "https" {
		return time.Time{}, false
	}
	certPEM, e := certificates.ReadPEM(c.Certificate)
	if e != nil {
		return time.Time{}, false
	}
	keyPEM, e := certificates.ReadPEM(c.PrivateKey)
	if e != nil {
		return time.Time{}, false
	}
	_, status, e := certificates.Parse(certPEM, keyPEM, certificateHost(c), time.Now())
	if e != nil {
		return time.Time{}, false
	}
	return certificates.RenewAfter(status.NotBefore, status.NotAfter), true
}

// publicIdentifier rejects names a public CA can never validate, before any
// request reaches it and counts against its limits.
func publicIdentifier(host string) error {
	if ip := net.ParseIP(host); ip != nil {
		if !ip.IsGlobalUnicast() || ip.IsPrivate() {
			return fmt.Errorf("%s is not a public IP address; trusted certificates need a public IP or a domain", host)
		}
		return nil
	}
	if !config.ValidHost(host) || !strings.Contains(host, ".") || strings.HasSuffix(strings.ToLower(host), ".local") {
		return fmt.Errorf("%s is not a public domain name", host)
	}
	return nil
}

func cloudflareToken(file string) (string, error) {
	token := os.Getenv(CloudflareTokenEnv)
	if file != "" {
		data, e := certificates.ReadPEM(file) // bounded regular-file read
		if e != nil {
			return "", errors.New("the Cloudflare token file must be a readable regular file")
		}
		token = string(data)
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", fmt.Errorf("Cloudflare validation needs an API token: set %s or use --cloudflare-token-file", CloudflareTokenEnv)
	}
	if !issuer.ValidToken(token) {
		return "", errors.New("the Cloudflare API token looks invalid")
	}
	return token, nil
}
