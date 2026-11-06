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
)

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
	if len(args) == 0 {
		return errors.New("usage: gtm-panel certificate status | install --cert FULLCHAIN --key PRIVATE_KEY [--host HOST] [--reload=false]")
	}
	fs := flag.NewFlagSet("certificate "+args[0], flag.ContinueOnError)
	path := fs.String("config", config.DefaultPath, "root-owned panel configuration")
	certPath := fs.String("cert", "", "ACME full-chain PEM source")
	keyPath := fs.String("key", "", "ACME private-key PEM source")
	host := fs.String("host", "", "public IP or domain covered by the certificate")
	reload := fs.Bool("reload", true, "reload the active public panel after installing")
	enableHTTPS := fs.Bool("enable-https", false, "switch an HTTP panel to HTTPS and restart only its public service")
	if e := fs.Parse(args[1:]); e != nil {
		return e
	}
	if fs.NArg() != 0 || (args[0] != "status" && args[0] != "install") {
		return errors.New("unknown certificate command or extra arguments")
	}
	if args[0] == "status" {
		c, e := config.Load(*path)
		if e != nil {
			return e
		}
		if c.Scheme() == "http" {
			return json.NewEncoder(os.Stdout).Encode(certificates.Status{Protocol: "http", Host: certificateHost(c)})
		}
		r, e := certificates.New(func() (certificates.Source, error) {
			return certificates.Source{Certificate: c.Certificate, Key: c.PrivateKey, Host: certificateHost(c)}, nil
		})
		if e != nil {
			return e
		}
		return json.NewEncoder(os.Stdout).Encode(r.Status())
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("install certificates locally as Linux root")
	}
	lease, e := certificates.Lock("/run/gre-manager-panel-install.lock")
	if e != nil {
		return e
	}
	defer lease.Close()
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	previous := c
	if c.Scheme() != "https" && !*enableHTTPS {
		return errors.New("use --enable-https for the initial HTTP-to-HTTPS switch; it restarts only the public panel")
	}
	if *enableHTTPS {
		c.Protocol = "https"
	}
	if *certPath == "" || *keyPath == "" {
		return errors.New("--cert and --key are required; provide file paths, never PEM or secrets as arguments")
	}
	if *host != "" && !config.ValidHost(*host) {
		return errors.New("invalid public host")
	}
	if *host != "" {
		c.PublicHost = *host
	}
	certPEM, e := certificates.ReadPEM(*certPath)
	if e != nil {
		return e
	}
	keyPEM, e := certificates.ReadPEM(*keyPath)
	if e != nil {
		return e
	}
	_, status, e := certificates.Parse(certPEM, keyPEM, certificateHost(c), time.Now())
	if e != nil {
		return e
	}
	material := append(append(append([]byte{}, certPEM...), '\n'), keyPEM...)
	if len(material) > certificates.MaxPEMBytes {
		return errors.New("combined certificate bundle exceeds 1 MiB")
	}
	var activate func() error
	if *reload {
		activate = func() error { return activateCertificate(ctx, previous.Scheme() != c.Scheme()) }
	}
	if e = publishCertificate(*path, previous, c, material, activate); e != nil {
		return e
	}
	fmt.Printf("Certificate installed for %s. Valid until %s. SHA-256: %s\n", status.Host, status.NotAfter.UTC().Format(time.RFC3339), status.Fingerprint)
	if !status.Trusted {
		fmt.Println("This certificate does not chain to this server's system trust store; clients may require private-CA trust.")
	}
	return nil
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
// the installer lock belong to certificateCommand, not to certificate I/O.
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
