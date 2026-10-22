package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/httpapi"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/ui"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/term"
)

const Version = "1.3.0"

func main() {
	if e := run(); e != nil {
		log.Print(e)
		os.Exit(1)
	}
}
func run() error {
	if len(os.Args) < 2 {
		return errors.New("usage: gtm-panel setup | serve | broker | reset-password | demo | version")
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	switch os.Args[1] {
	case "version":
		fmt.Println("v" + Version)
		return nil
	case "metrics-plan":
		fs := flag.NewFlagSet("metrics-plan", flag.ContinueOnError)
		state := fs.String("state-file", "", "read-only TSV state")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		if *state == "" {
			return errors.New("--state-file is required")
		}
		info, e := os.Stat(*state)
		if e != nil {
			return e
		}
		if !info.Mode().IsRegular() || info.Size() > 1048576 {
			return errors.New("state must be a regular file under 1 MiB")
		}
		data, e := os.ReadFile(*state)
		if e != nil {
			return e
		}
		connections, _, e := model.ParseState(string(data))
		if e != nil {
			return e
		}
		fmt.Print(control.MetricsRules(control.Inventory{Connections: connections}, control.MetricsSettings{Enabled: true, Interval: 60}))
		return nil
	case "address":
		c, e := config.Load(config.DefaultPath)
		if e != nil {
			return e
		}
		fmt.Printf("HTTPS listener: %s\nUse your server's reachable IP with this port.\n", c.Listen)
		return nil
	case "setup":
		return setup(os.Args[2:])
	case "reset-password":
		return reset(os.Args[2:])
	case "broker":
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return errors.New("broker requires Linux root")
		}
		manager := control.NewManager()
		metrics, e := control.NewMetrics(manager.Runner, "/var/lib/gre-manager-panel/metrics.json")
		if e != nil {
			return e
		}
		manager.Metrics = metrics
		return (&control.Broker{Manager: manager}).Listen(ctx, config.Socket)
	case "serve":
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			return errors.New("run the public panel as the grepanel user, not root")
		}
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		path := fs.String("config", config.DefaultPath, "configuration path")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		c, e := config.Load(*path)
		if e != nil {
			return e
		}
		server := httpapi.New(ctx, auth.New(c.Username, c.PasswordHash, true), control.NewUnixClient(c.BrokerSocket), ui.Handler(), false)
		return serve(ctx, c.Listen, server, c.Certificate, c.PrivateKey)
	case "demo":
		fs := flag.NewFlagSet("demo", flag.ContinueOnError)
		address := fs.String("listen", "127.0.0.1:8790", "loopback address")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		host, _, e := net.SplitHostPort(*address)
		if e != nil || net.ParseIP(host) == nil || !net.ParseIP(host).IsLoopback() {
			return errors.New("demo only binds loopback")
		}
		hash, e := bcrypt.GenerateFromPassword([]byte("demo-panel-12345"), 12)
		if e != nil {
			return e
		}
		server := httpapi.New(ctx, auth.New("demo", string(hash), false), control.NewDemo(), ui.Handler(), true)
		fmt.Printf("Demo only: http://%s | username: demo | password: demo-panel-12345\n", *address)
		return serve(ctx, *address, server, "", "")
	default:
		return errors.New("unknown command")
	}
}
func serve(ctx context.Context, address string, handler http.Handler, certificate, key string) error {
	server := &http.Server{Addr: address, Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16384, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12}}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		server.Shutdown(shutdown)
	}()
	var e error
	if certificate == "" {
		e = server.ListenAndServe()
	} else {
		e = server.ListenAndServeTLS(certificate, key)
	}
	if errors.Is(e, http.ErrServerClosed) {
		return nil
	}
	return e
}
func ask(reader *bufio.Reader, label, fallback string) (string, error) {
	fmt.Printf("%s [%s]: ", label, fallback)
	text, e := reader.ReadString('\n')
	if e != nil {
		return "", e
	}
	text = strings.TrimSpace(text)
	if text == "" {
		text = fallback
	}
	return text, nil
}
func password() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("password entry requires a terminal; passwords are never accepted as command-line arguments")
	}
	fmt.Print("Admin password (12–72 bytes): ")
	first, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if e != nil {
		return "", e
	}
	fmt.Print("Confirm password: ")
	second, e := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if e != nil {
		return "", e
	}
	if string(first) != string(second) || len(first) < 12 || len(first) > 72 {
		return "", errors.New("passwords must match and contain 12–72 bytes")
	}
	return string(first), nil
}
func setup(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ContinueOnError)
	path := fs.String("config", config.DefaultPath, "configuration path")
	public := fs.String("public-ip", "", "public IP for certificate SAN")
	if e := fs.Parse(args); e != nil {
		return e
	}
	if *public != "" && net.ParseIP(*public) == nil {
		return errors.New("public IP must be a literal IPv4 or IPv6 address")
	}
	if _, e := os.Lstat(*path); e == nil {
		return errors.New("configuration already exists; use reset-password or edit the listen address locally")
	}
	reader := bufio.NewReader(os.Stdin)
	bind, e := ask(reader, "Listen IP", "0.0.0.0")
	if e != nil {
		return e
	}
	value, e := ask(reader, "Panel port (empty = random available port)", "0")
	if e != nil {
		return e
	}
	port, e := strconv.Atoi(value)
	if e != nil {
		return e
	}
	user, e := ask(reader, "Admin username", "admin")
	if e != nil {
		return e
	}
	secret, e := password()
	if e != nil {
		return e
	}
	ips := []string{*public}
	addresses, _ := net.InterfaceAddrs()
	for _, address := range addresses {
		host, _, e := net.ParseCIDR(address.String())
		if e == nil {
			ips = append(ips, host.String())
		}
	}
	c, fingerprint, e := config.New(*path, bind, port, user, secret, ips)
	if e != nil {
		return e
	}
	c.PublicIP = *public
	if e = config.Save(*path, c, 0640); e != nil {
		return e
	}
	_, chosen, _ := net.SplitHostPort(c.Listen)
	host := *public
	if host == "" {
		host = bind
	}
	fmt.Printf("\nPanel URL: https://%s\nCertificate SHA-256: %s\nSelf-signed HTTPS: verify this fingerprint before trusting the certificate.\n", net.JoinHostPort(host, chosen), fingerprint)
	return nil
}
func reset(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ContinueOnError)
	path := fs.String("config", config.DefaultPath, "configuration path")
	if e := fs.Parse(args); e != nil {
		return e
	}
	c, e := config.Load(*path)
	if e != nil {
		return e
	}
	secret, e := password()
	if e != nil {
		return e
	}
	hash, e := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if e != nil {
		return e
	}
	c.PasswordHash = string(hash)
	if e = config.Save(*path, c, 0640); e != nil {
		return e
	}
	fmt.Println("Password updated. Restart gre-manager-panel.service to revoke existing sessions.")
	return nil
}
