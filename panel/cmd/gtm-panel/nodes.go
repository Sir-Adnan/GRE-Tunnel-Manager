package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/nodes"
	"golang.org/x/term"
)

func nodeCommand(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: gtm-panel nodes init | enroll | agent | protocol")
	}
	fs := flag.NewFlagSet("nodes "+args[0], flag.ContinueOnError)
	switch args[0] {
	case "protocol":
		fmt.Println(nodes.Protocol)
		return nil
	case "operations-version":
		fmt.Println("1")
		return nil
	case "check":
		path := fs.String("identity", nodes.DefaultAgentPath, "private identity file")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		return nodes.CheckIdentity(*path)
	case "check-controller":
		dir := fs.String("dir", nodes.DefaultControllerDir, "private Controller directory")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		return nodes.CheckController(*dir)
	case "init":
		dir := fs.String("dir", nodes.DefaultControllerDir, "private controller state directory")
		address := fs.String("url", "", "https://IP_OR_DOMAIN:PORT reached by agents")
		listen := fs.String("listen", "0.0.0.0:9443", "dedicated TLS control listener")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		if e := nodes.Init(*dir, *address, *listen); e != nil {
			return e
		}
		fmt.Println("Controller initialized. Restart the panel and allow its dedicated control TCP port. Keep its state owned by the panel service account.")
		return nil
	case "enroll":
		path := fs.String("identity", nodes.DefaultAgentPath, "private identity file")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		if fs.NArg() != 0 {
			return errors.New("invitation must be entered at the hidden terminal prompt")
		}
		if !term.IsTerminal(int(os.Stdin.Fd())) {
			return errors.New("enrollment requires a terminal; never pass invitation secrets as arguments")
		}
		fmt.Print("One-time enrollment code (hidden): ")
		b, e := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Println()
		if e != nil {
			return e
		}
		if e = nodes.Enroll(ctx, *path, strings.TrimSpace(string(b))); e != nil {
			return e
		}
		fmt.Println("Agent enrolled. Identity saved privately; no remote writes are enabled.")
		return nil
	case "agent":
		operations := fs.Bool("operations", false, "explicitly enable leased paired-create tasks")
		path := fs.String("identity", nodes.DefaultAgentPath, "private identity file")
		socket := fs.String("socket", "/run/gre-manager-agent/broker.sock", "local read-only broker socket")
		if e := fs.Parse(args[1:]); e != nil {
			return e
		}
		if fs.NArg() != 0 {
			return errors.New("unexpected arguments")
		}
		if runtime.GOOS == "linux" && os.Geteuid() == 0 {
			return errors.New("run the network Agent as the greagent service user, not root")
		}
		return (nodes.Agent{Path: *path, Version: Version, Operations: *operations, Client: control.NewUnixClient(*socket), Notify: func(code string) { log.Printf("agent state: %s", code) }}).Run(ctx)
	default:
		return errors.New("unknown nodes command")
	}
}
func startNodes(ctx context.Context, dir string) (*nodes.Hub, <-chan error, error) {
	if _, e := os.Stat(dir + "/controller.json"); os.IsNotExist(e) {
		return nil, nil, nil
	}
	h, e := nodes.Open(dir)
	if e != nil {
		return nil, nil, e
	}
	server, e := h.Server()
	if e != nil {
		h.Close()
		return nil, nil, e
	}
	listener, e := net.Listen("tcp", server.Addr)
	if e != nil {
		h.Close()
		return nil, nil, e
	}
	errc := make(chan error, 1)
	go func() {
		e := server.ServeTLS(listener, "", "")
		if errors.Is(e, http.ErrServerClosed) {
			e = nil
		}
		errc <- e
	}()
	go func() {
		<-ctx.Done()
		stop, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if server.Shutdown(stop) != nil {
			server.Close()
		}
		h.Close()
	}()
	return h, errc, nil
}
