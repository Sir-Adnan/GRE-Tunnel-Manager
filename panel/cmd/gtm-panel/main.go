package main

import (
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
	"syscall"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/auth"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/httpapi"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/model"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/nodes"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/setup"
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
	case "nodes":
		return nodeCommand(ctx, os.Args[2:])
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
		fs := flag.NewFlagSet("address", flag.ContinueOnError)
		path := fs.String("config", config.DefaultPath, "configuration path")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		c, e := config.Load(*path)
		if e != nil {
			return e
		}
		if address := c.URL(); address != "" {
			fmt.Printf("Panel URL: %s\nUsername: %s\n", address, c.Username)
		} else {
			fmt.Printf("%s listener: %s\nUse your server's reachable IP with this port.\n", c.Scheme(), c.Listen)
		}
		return nil
	case "setup":
		return (setup.Console{In: os.Stdin, Out: os.Stdout, Password: password, Discover: setup.Discover}).Run(ctx, os.Args[2:])
	case "setup-version":
		fmt.Println("2")
		return nil
	case "reset-password":
		return reset(os.Args[2:])
	case "broker":
		if runtime.GOOS != "linux" || os.Geteuid() != 0 {
			return errors.New("broker requires Linux root")
		}
		manager := control.NewManager()
		fs := flag.NewFlagSet("broker", flag.ContinueOnError)
		readOnly := fs.Bool("read-only", false, "inventory-only broker for agents")
		nodeOperations := fs.Bool("node-operations", false, "allow leased paired-create tasks on an otherwise read-only Agent broker")
		socket := fs.String("socket", config.Socket, "private Unix socket")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		var nodeExecutor *control.NodeExecutor
		if !*readOnly || *nodeOperations {
			nodeExecutor = &control.NodeExecutor{Manager: manager, Directory: "/var/lib/gre-manager-node-operations"}
		}
		if *readOnly {
			return (&control.Broker{Manager: manager, ReadOnly: true, Nodes: nodeExecutor}).Listen(ctx, *socket)
		}
		metrics, e := control.NewMetrics(manager.Runner, "/var/lib/gre-manager-panel/metrics.json")
		if e != nil {
			return e
		}
		manager.Metrics = metrics
		return (&control.Broker{Manager: manager, Nodes: nodeExecutor}).Listen(ctx, *socket)
	case "serve":
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			return errors.New("run the public panel as the grepanel user, not root")
		}
		fs := flag.NewFlagSet("serve", flag.ContinueOnError)
		path := fs.String("config", config.DefaultPath, "configuration path")
		nodesDir := fs.String("nodes-dir", nodes.DefaultControllerDir, "optional private Controller directory")
		if e := fs.Parse(os.Args[2:]); e != nil {
			return e
		}
		c, e := config.Load(*path)
		if e != nil {
			return e
		}
		serviceCtx, cancel := context.WithCancel(ctx)
		defer cancel()
		h, nodeErrors, e := startNodes(serviceCtx, *nodesDir)
		if e != nil {
			return e
		}
		server := httpapi.New(serviceCtx, auth.New(c.Username, c.PasswordHash, c.Scheme() == "https"), control.NewUnixClient(c.BrokerSocket), ui.Handler(), false)
		server.Nodes = h
		if h != nil {
			go h.RunOperations(serviceCtx, server.Client)
		}
		nodeStopped := make(chan error, 1)
		if nodeErrors != nil {
			go func() {
				e := <-nodeErrors
				nodeStopped <- e
				cancel()
			}()
		}
		var result error
		if c.Scheme() == "http" {
			result = serve(serviceCtx, c.Listen, server, "", "")
		} else {
			result = serve(serviceCtx, c.Listen, server, c.Certificate, c.PrivateKey)
		}
		select {
		case e := <-nodeStopped:
			if e != nil {
				return e
			}
		default:
		}
		return result
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
func password() (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		return "", errors.New("password entry requires a terminal; passwords are never accepted as command-line arguments")
	}
	for attempt := 0; attempt < 3; attempt++ {
		fmt.Print("Admin password (8+ characters, at most 72 bytes): ")
		first, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if e != nil {
			return "", e
		}
		if e = config.ValidatePassword(string(first)); e != nil {
			fmt.Println(e)
			continue
		}
		fmt.Print("Confirm password: ")
		second, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if e != nil {
			return "", e
		}
		if string(first) != string(second) {
			fmt.Println("Passwords do not match. Please try again.")
			continue
		}
		return string(first), nil
	}
	return "", errors.New("password entry failed after three attempts")
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
