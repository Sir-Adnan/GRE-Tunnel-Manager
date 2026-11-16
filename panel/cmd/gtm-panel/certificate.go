package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/issuer"
)

const installLock = "/run/gre-manager-panel-install.lock"

const certificateUsage = `usage: gtm-panel certificate COMMAND [options]

  status        Show the certificate on disk and its renewal state (JSON)
  issue         Get a trusted Let's Encrypt certificate and renew it automatically
  renew         Renew a managed certificate when due (run by the systemd timer)
  install       Use a certificate from Certbot, acme.sh or another client
  self-signed   Return to a new self-signed certificate

Run "gtm-panel certificate COMMAND -h" for the options of one command.`

func certificateHost(c config.Config) string {
	if c.PublicHost != "" {
		return c.PublicHost
	}
	if c.PublicIP != "" {
		return c.PublicIP
	}
	host, _, _ := net.SplitHostPort(c.Listen)
	return host
}

func certificateCommand(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		fmt.Println(certificateUsage)
		return nil
	}
	command, rest := args[0], args[1:]
	switch command {
	case "status":
		return certificateStatus(rest)
	case "install":
		return certificateInstall(ctx, rest)
	case "issue":
		return certificateIssue(ctx, rest)
	case "renew":
		return certificateRenew(ctx, rest)
	case "self-signed":
		return certificateSelfSigned(ctx, rest)
	}
	return errors.New("unknown certificate command; run gtm-panel certificate --help")
}

func certificateFlags(name string) (*flag.FlagSet, *string) {
	fs := flag.NewFlagSet("certificate "+name, flag.ContinueOnError)
	return fs, fs.String("config", config.DefaultPath, "root-owned panel configuration")
}

func parseOnly(fs *flag.FlagSet, args []string) error {
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected arguments: " + fmt.Sprint(fs.Args()))
	}
	return nil
}

func certificateStatus(args []string) error {
	fs, path := certificateFlags("status")
	if e := parseOnly(fs, args); e != nil {
		return e
	}
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	status := certificates.Status{Protocol: "http", Host: certificateHost(c)}
	if c.Scheme() == "https" {
		r, e := certificates.New(func() (certificates.Source, error) {
			return certificates.Source{Certificate: c.Certificate, Key: c.PrivateKey, Host: certificateHost(c)}, nil
		})
		if e != nil {
			return e
		}
		status = r.Status()
	}
	if renewal, e := certificates.LoadRenewal(filepath.Join(filepath.Dir(*path), filepath.Base(certificates.RenewalPath))); e == nil {
		status.Renewal = &renewal
	}
	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(status)
}

func certificateInstall(ctx context.Context, args []string) error {
	fs, path := certificateFlags("install")
	certPath := fs.String("cert", "", "full-chain PEM file from the ACME client")
	keyPath := fs.String("key", "", "private-key PEM file from the ACME client")
	host := fs.String("host", "", "public IP or domain covered by the certificate")
	reload := fs.Bool("reload", true, "reload the running public panel after installing")
	enableHTTPS := fs.Bool("enable-https", false, "switch an HTTP panel to HTTPS (restarts only the public panel)")
	if e := parseOnly(fs, args); e != nil {
		return e
	}
	if *certPath == "" || *keyPath == "" {
		return errors.New("--cert and --key are required; provide file paths, never PEM or secrets as arguments")
	}
	lease, e := lockAsRoot()
	if e != nil {
		return e
	}
	defer lease.Close()
	certPEM, e := certificates.ReadPEM(*certPath)
	if e != nil {
		return e
	}
	keyPEM, e := certificates.ReadPEM(*keyPath)
	if e != nil {
		return e
	}
	status, e := applyCertificate(ctx, change{configPath: *path, host: *host, enableHTTPS: *enableHTTPS, reload: *reload, certPEM: certPEM, keyPEM: keyPEM})
	if e != nil {
		return e
	}
	// An external client now owns renewal; a managed recipe would fight it.
	store := storeFor(*path)
	if e = store.Disable(); e != nil {
		return e
	}
	saveRecord(store, certificates.Renewal{Source: certificates.SourceExternal, Host: status.Host, NotAfter: status.NotAfter})
	fmt.Printf("Certificate installed for %s. Valid until %s. SHA-256: %s\n", status.Host, status.NotAfter.UTC().Format(time.RFC3339), status.Fingerprint)
	if !status.Trusted {
		fmt.Println("This certificate does not chain to this server's system trust store; clients may require private-CA trust.")
	}
	return nil
}

func lockAsRoot() (*os.File, error) {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return nil, errors.New("change the panel certificate locally as Linux root (sudo)")
	}
	return certificates.Lock(installLock)
}

// storeFor keeps the account directory and status record beside the
// configuration, so tests and alternate configurations stay self-contained.
func storeFor(configPath string) issuer.Store {
	dir := filepath.Dir(configPath)
	return issuer.Store{Dir: filepath.Join(dir, "acme"), StatusPath: filepath.Join(dir, filepath.Base(certificates.RenewalPath)), ConfigPath: configPath}
}

// saveRecord is informational: a failed status write never undoes a
// certificate that is already installed and loaded.
func saveRecord(store issuer.Store, record certificates.Renewal) {
	if e := store.SaveRecord(record); e != nil {
		fmt.Fprintln(os.Stderr, "Warning: the certificate status record could not be saved:", e)
	}
}

type change struct {
	configPath          string
	host                string // optional new public host
	enableHTTPS, reload bool
	certPEM, keyPEM     []byte
}

// applyCertificate validates new material against the (possibly updated)
// public host, publishes it with rollback and activates it.
func applyCertificate(ctx context.Context, ch change) (certificates.Status, error) {
	var status certificates.Status
	c, e := config.Load(ch.configPath)
	if e != nil {
		return status, e
	}
	previous := c
	if c.Scheme() != "https" && !ch.enableHTTPS {
		return status, errors.New("this panel uses HTTP; add --enable-https to switch it to HTTPS (restarts only the public panel)")
	}
	c.Protocol = "https"
	if ch.host != "" {
		if !config.ValidHost(ch.host) {
			return status, errors.New("invalid public host")
		}
		c.PublicHost = ch.host
		if net.ParseIP(ch.host) != nil {
			c.PublicIP = ch.host
		}
	}
	_, status, e = certificates.Parse(ch.certPEM, ch.keyPEM, certificateHost(c), time.Now())
	if e != nil {
		return status, e
	}
	material := append(append(append([]byte{}, ch.certPEM...), '\n'), ch.keyPEM...)
	if len(material) > certificates.MaxPEMBytes {
		return status, errors.New("combined certificate bundle exceeds 1 MiB")
	}
	var activate func() error
	if ch.reload {
		activate = func() error { return activateCertificate(ctx, previous.Scheme() != c.Scheme()) }
	}
	return status, publishCertificate(ch.configPath, previous, c, material, activate)
}

func activateCertificate(ctx context.Context, restart bool) error {
	step, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	e := exec.CommandContext(step, "systemctl", "is-active", "--quiet", "gre-manager-panel.service").Run()
	if e != nil {
		var exit *exec.ExitError
		if errors.As(e, &exit) && (exit.ExitCode() == 3 || exit.ExitCode() == 4) {
			return nil
		}
		return errors.New("could not inspect the public panel service")
	}
	verb := "reload"
	if restart {
		verb = "restart"
	}
	if e = exec.CommandContext(step, "systemctl", verb, "gre-manager-panel.service").Run(); e != nil {
		return errors.New("public panel certificate activation failed")
	}
	return nil
}

// Publication is independently testable; command parsing, root authorization and
// the installer lock belong to the commands, not to certificate I/O.
func publishCertificate(path string, previous, c config.Config, material []byte, activate func() error) error {
	bundle := filepath.Join(filepath.Dir(path), "https.pem")
	var oldBundle []byte
	if info, e := os.Lstat(bundle); e == nil {
		if !info.Mode().IsRegular() {
			return errors.New("managed TLS bundle must not be a link or special file")
		}
		oldBundle, e = certificates.ReadPEM(bundle)
		if e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	if e := config.SaveMaterial(bundle, path, material); e != nil {
		return e
	}
	c.Certificate, c.PrivateKey = bundle, bundle
	rollback := func() error {
		if e := config.Save(path, previous, 0640); e != nil {
			return e
		}
		if oldBundle == nil {
			return os.Remove(bundle)
		}
		return config.SaveMaterial(bundle, path, oldBundle)
	}
	if e := config.Save(path, c, 0640); e != nil {
		return errors.Join(e, rollback())
	}
	if activate != nil {
		if e := activate(); e != nil {
			recovery := rollback()
			if recovery == nil {
				recovery = activate()
			}
			if recovery != nil {
				return errors.Join(errors.New("certificate activation failed; recovery needs local inspection"), e, recovery)
			}
			return errors.Join(errors.New("certificate activation failed; previous configuration restored"), e, recovery)
		}
	}
	return nil
}
