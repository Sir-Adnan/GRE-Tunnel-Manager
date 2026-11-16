// Package gtm is the server command line: it installs, updates and maintains
// the web panel and the Agent. Tunnels are managed in the panel, not here.
//
// Commands are thin: they gather options (flags or a short form), call the
// install package, and present the result with the tui package.
package gtm

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

// App holds everything a command needs. Tests replace the system parts.
type App struct {
	UI        *tui.UI
	Installer *install.Installer
	Release   release.Client
	Version   string
	// Root reports whether the process may change the system.
	Root bool
	// Getenv reads the environment (secrets are passed by variable name).
	Getenv   func(string) string
	Discover func(context.Context) (string, error)
}

// ErrReported is a failure that was already shown to the operator (for
// example by the new release's installer during an update).
var ErrReported = errors.New("failed; see the messages above")

// Main runs one gtm command line.
func (a *App) Main(ctx context.Context, args []string) error {
	name, rest := "", args
	if len(args) > 0 {
		name, rest = args[0], args[1:]
	}
	run, ok := a.commands()[name]
	if !ok {
		return fmt.Errorf("unknown command %q; run gtm help", name)
	}
	e := run(ctx, rest)
	if errors.Is(e, tui.ErrCancelled) {
		a.UI.Hint("Cancelled; nothing was changed.")
		return nil
	}
	if errors.Is(e, flag.ErrHelp) {
		return nil
	}
	return e
}

type command func(context.Context, []string) error

func (a *App) commands() map[string]command {
	c := map[string]command{
		"":           a.home,
		"install":    a.install,
		"update":     a.update,
		"status":     a.status,
		"https":      a.https,
		"port":       a.port,
		"password":   a.password,
		"2fa":        a.twoFactor,
		"logs":       a.logs,
		"agent":      a.agent,
		"controller": a.controller,
		"remove":     a.remove,
		"version":    a.version,
		"help":       a.help,
		// Run by the daily systemd timer; not listed in the help.
		"update-check": a.updateCheck,
	}
	for alias, target := range map[string]string{"repair": "install", "upgrade": "update", "certificate": "https", "uninstall": "remove", "two-factor": "2fa", "--version": "version", "-v": "version", "--help": "help", "-h": "help"} {
		c[alias] = c[target]
	}
	return c
}

const usage = `Installs, updates and maintains the web panel. Tunnels are managed in the panel.

Usage
  gtm                         Status and menu
  gtm install  [options]      Install or repair the panel (gtm install --help)
  gtm update   [--check]      Update to the latest release; rolls back on failure
  gtm status   [--json]       Services, address, certificate and updates
  gtm https    [command]      Trusted certificates: issue, renew, self-signed, status
  gtm port     [PORT]         Move the panel to another TCP port
  gtm password [--user NAME]  Set a new login password
  gtm 2fa off                 Turn two-factor sign-in off (lost phone)
  gtm logs     [UNIT] [-f]    panel, broker, certificate, update or agent logs
  gtm agent    install|remove|status
  gtm controller enable --url https://IP_OR_DOMAIN:9443
  gtm remove                  Remove the panel; tunnels keep running

Run a command with --help for its options.`

func (a *App) help(context.Context, []string) error {
	a.UI.Header("GRE Tunnel Manager", "v"+a.Version, "")
	a.UI.Blank()
	for _, line := range strings.Split(usage, "\n") {
		switch line {
		case "Usage":
			a.UI.Section(line)
		case "":
			a.UI.Blank()
		default:
			a.UI.Text("%s", line)
		}
	}
	a.UI.Blank()
	return nil
}

func (a *App) version(context.Context, []string) error {
	fmt.Fprintf(a.UI.Out(), "v%s\n", a.Version)
	return nil
}

// flags creates a flag set whose --help prints a short, styled usage.
func (a *App) flags(name, summary string) *flag.FlagSet {
	fs := flag.NewFlagSet("gtm "+name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {
		a.UI.Header("gtm "+name, "", summary)
		a.UI.Blank()
		var rows []tui.Row
		fs.VisitAll(func(f *flag.Flag) {
			if strings.HasPrefix(f.Usage, "alias") || f.Usage == "" {
				return
			}
			kind, usage := flag.UnquoteUsage(f)
			label := "--" + f.Name
			switch kind {
			case "string":
				label += " VALUE"
			case "int":
				label += " N"
			}
			rows = append(rows, tui.Row{Label: label, Value: usage})
		})
		a.UI.Rows(rows)
		a.UI.Blank()
	}
	return fs
}

func (a *App) parse(fs *flag.FlagSet, args []string) error {
	if e := fs.Parse(args); e != nil {
		if errors.Is(e, flag.ErrHelp) {
			return e // flag already printed the usage
		}
		return fmt.Errorf("%v (see %s --help)", e, fs.Name())
	}
	return nil
}

func (a *App) requireRoot() error {
	if !a.Root {
		return errors.New("run gtm with sudo or as root")
	}
	return nil
}

// generatePassword returns 32 URL-safe characters (192 random bits).
func generatePassword() (string, error) {
	data := make([]byte, 24)
	if _, e := rand.Read(data); e != nil {
		return "", e
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

// secretFromEnv reads a secret by variable name; the value never appears in
// argv, process listings or shell history.
func (a *App) secretFromEnv(name string) (string, error) {
	value := a.Getenv(name)
	if value == "" {
		return "", fmt.Errorf("environment variable %s is empty; with sudo, pass it through: sudo --preserve-env=%s gtm ...", name, name)
	}
	return value, nil
}
