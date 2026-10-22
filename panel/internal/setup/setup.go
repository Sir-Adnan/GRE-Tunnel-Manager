package setup

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
)

// Console keeps terminal IO and secret entry injectable without accepting secrets in argv.
type Console struct {
	In       io.Reader
	Out      io.Writer
	Password func() (string, error)
	Discover func(context.Context) (string, error)
}

func (c Console) Run(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	fs.SetOutput(c.Out)
	path := fs.String("config", config.DefaultPath, "configuration path")
	quick := fs.Bool("quick", false, "generate administrator credentials without further prompts")
	protocol := fs.String("protocol", "", "https (default) or http (unencrypted)")
	host := fs.String("address", "", "reachable server IP or ASCII domain; empty discovers public IP")
	oldIP := fs.String("public-ip", "", "legacy alias for --address (IP only)")
	listen := fs.String("listen", "", "local listen IP; defaults to IPv4 or IPv6 wildcard")
	port := fs.Int("port", 0, "TCP port; 0 selects an available random port")
	user := fs.String("username", "admin", "administrator username")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if fs.NArg() != 0 {
		return errors.New("unexpected setup arguments")
	}
	nonInteractive := *quick
	if *oldIP != "" {
		if *host != "" || net.ParseIP(*oldIP) == nil {
			return errors.New("use one valid --address or --public-ip")
		}
		*host = *oldIP
	}
	if *protocol != "" && *protocol != "http" && *protocol != "https" {
		return errors.New("protocol must be https or http")
	}
	if *port < 0 || *port > 65535 {
		return errors.New("port must be 0–65535")
	}
	if *host != "" && !config.ValidHost(*host) {
		return errors.New("address must be an IP or ASCII domain, without a scheme, path or port")
	}
	if *listen != "" && net.ParseIP(*listen) == nil {
		return errors.New("listen must be a local IP address")
	}
	if !config.UserPattern.MatchString(*user) {
		return errors.New("invalid administrator username")
	}
	if _, e := os.Lstat(*path); !os.IsNotExist(e) {
		return errors.New("configuration already exists or cannot be inspected; installation preserves credentials, use reset-password for recovery")
	}
	reader := bufio.NewReader(c.In)
	ask := func(label, fallback string, valid func(string) bool) (string, error) {
		for {
			fmt.Fprintf(c.Out, "  %s [%s]: ", label, fallback)
			value, e := reader.ReadString('\n')
			if e != nil {
				return "", errors.New("setup needs a terminal; use --quick for generated credentials")
			}
			value = strings.TrimSpace(value)
			if value == "" {
				value = fallback
			}
			if valid(value) {
				return value, nil
			}
			fmt.Fprintln(c.Out, "  Invalid choice. Please try again.")
		}
	}
	choice := func(values ...string) func(string) bool {
		return func(s string) bool {
			for _, v := range values {
				if s == v {
					return true
				}
			}
			return false
		}
	}
	fmt.Fprintln(c.Out, "\n  GRE TUNNEL MANAGER / WEB PANEL\n  ----------------------------------------")
	if !*quick {
		fmt.Fprintln(c.Out, "  [1] Quick setup     Random port + strong generated password\n  [2] Custom setup    Choose your port and credentials")
		value, e := ask("Setup", "1", choice("1", "2"))
		if e != nil {
			return e
		}
		*quick = value == "1"
	}
	if *protocol == "" {
		*protocol = "https"
		if !nonInteractive {
			fmt.Fprintln(c.Out, "\n  [1] HTTPS (recommended)\n  [2] HTTP  (unencrypted)")
			value, e := ask("Access", "1", choice("1", "2"))
			if e != nil {
				return e
			}
			if value == "2" {
				*protocol = "http"
			}
		}
	}
	if *host == "" {
		fmt.Fprintln(c.Out, "\n  Detecting public IP...")
		var e error
		*host, e = c.Discover(ctx)
		if e != nil {
			if *quick {
				return e
			}
			fmt.Fprintln(c.Out, "  Discovery unavailable. Enter a reachable IP or domain.")
		}
	}
	if !*quick {
		value, e := ask("Server IP or domain", *host, config.ValidHost)
		if e != nil {
			return e
		}
		*host = value
		value, e = ask("Panel port (0 = random)", strconv.Itoa(*port), func(v string) bool { p, err := strconv.Atoi(v); return err == nil && p >= 0 && p <= 65535 })
		if e != nil {
			return e
		}
		*port, _ = strconv.Atoi(value)
		value, e = ask("Admin username", *user, config.UserPattern.MatchString)
		if e != nil {
			return e
		}
		*user = value
	}
	if !config.ValidHost(*host) {
		return errors.New("a reachable IP or domain is required")
	}
	if *listen == "" {
		*listen = "0.0.0.0"
		if ip := net.ParseIP(*host); ip != nil && ip.To4() == nil {
			*listen = "::"
		}
	}
	if *protocol == "http" {
		fmt.Fprintln(c.Out, "\n  HTTP selected: login and management traffic are not encrypted.")
	}
	var secret string
	var e error
	if *quick {
		data := make([]byte, 24)
		if _, e = rand.Read(data); e != nil {
			return e
		}
		secret = base64.RawURLEncoding.EncodeToString(data)
	} else {
		secret, e = c.Password()
		if e != nil {
			return e
		}
	}
	addresses := []string{}
	if values, e := net.InterfaceAddrs(); e == nil {
		for _, value := range values {
			if ip, _, e := net.ParseCIDR(value.String()); e == nil {
				addresses = append(addresses, ip.String())
			}
		}
	}
	cfg, fingerprint, e := config.Create(*path, config.Options{Listen: *listen, Port: *port, Username: *user, Password: secret, Protocol: *protocol, PublicHost: *host, Addresses: addresses})
	if e != nil {
		return e
	}
	fmt.Fprintf(c.Out, "\n  Panel URL: %s\n  Username:  %s\n", cfg.URL(), cfg.Username)
	if *quick {
		fmt.Fprintf(c.Out, "  Password:  %s\n  Save this password now; it will not be shown again.\n", secret)
	}
	if fingerprint != "" {
		fmt.Fprintf(c.Out, "  Certificate SHA-256: %s\n  Self-signed HTTPS: verify this fingerprint through SSH.\n", fingerprint)
	}
	fmt.Fprintln(c.Out, "  Allow the chosen TCP port in your server/provider firewall.")
	return nil
}
