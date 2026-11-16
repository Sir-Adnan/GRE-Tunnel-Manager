package gtm

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/config"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

func (a *App) port(ctx context.Context, args []string) error {
	fs := a.flags("port", "Move the panel to another TCP port. Only the panel restarts; a failed start restores the old port.")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if fs.NArg() > 1 {
		return errors.New("usage: gtm port [PORT]")
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	text := fs.Arg(0)
	if text == "" {
		if !a.UI.Interactive && !a.UI.Accessible {
			return errors.New("usage: gtm port PORT")
		}
		if e := a.UI.Input("New panel port", "1–65535. Avoid 80 while Let's Encrypt verifies over port 80.", "2053", &text, func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("enter a port")
			}
			return validPortText(s)
		}); e != nil {
			return e
		}
	}
	port, e := strconv.Atoi(strings.TrimSpace(text))
	if e != nil {
		return errors.New("the port must be a number from 1 to 65535")
	}
	c, e := a.Installer.ChangePort(ctx, port)
	if e != nil {
		return e
	}
	notes := []string{fmt.Sprintf("Allow TCP %d in the server and provider firewall.", port), "Close the old port there once you have signed in."}
	if port == 80 {
		notes = append(notes, "Let's Encrypt renewal over port 80 cannot run while the panel uses it.")
	}
	a.UI.Card("Port changed", []tui.Row{{Label: "Address", Value: c.URL()}}, notes...)
	a.UI.Blank()
	return nil
}

func (a *App) password(ctx context.Context, args []string) error {
	fs := a.flags("password", "Set a new login password. Every signed-in session is signed out.")
	user := fs.String("user", "", "Also change the login name")
	fs.StringVar(user, "username", "", "alias of --user")
	generate := fs.Bool("generate", false, "Generate a strong password and show it once")
	fromEnv := fs.String("password-env", "", "Read the password from this environment variable")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if *user != "" && !config.UserPattern.MatchString(*user) {
		return errors.New("--user must be 3–40 ASCII letters, digits, dots, dashes or underscores")
	}
	if *generate && *fromEnv != "" {
		return errors.New("use --generate or --password-env, not both")
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	secret, shown := "", false
	switch {
	case *fromEnv != "":
		var e error
		if secret, e = a.secretFromEnv(*fromEnv); e != nil {
			return e
		}
	case *generate:
		shown = true
	case a.UI.Interactive || a.UI.Accessible:
		mode := "generate"
		if e := tui.Select(a.UI, "New password", "Every signed-in session is signed out.", []tui.Choice[string]{
			{Label: "Generate a strong password  shown once", Value: "generate"},
			{Label: "Choose my own", Value: "own"},
		}, &mode); e != nil {
			return e
		}
		if mode == "own" {
			if e := a.UI.Secret("Password", &secret, config.ValidatePassword); e != nil {
				return e
			}
		} else {
			shown = true
		}
	default:
		return errors.New("pass --generate or --password-env NAME when no terminal is attached")
	}
	if shown {
		var e error
		if secret, e = generatePassword(); e != nil {
			return e
		}
	}
	c, e := a.Installer.SetCredentials(ctx, *user, secret)
	if e != nil {
		return e
	}
	rows := []tui.Row{{Label: "Address", Value: c.URL()}, {Label: "Login", Value: c.Username}}
	var notes []string
	if shown {
		rows = append(rows, tui.Row{Label: "Password", Value: secret})
		notes = append(notes, "Save the password now; it is not shown again.")
	}
	a.UI.Card("Login updated", rows, notes...)
	a.UI.Blank()
	return nil
}

var logUnits = map[string][]string{
	"panel":       {install.PanelUnit},
	"broker":      {install.BrokerUnit},
	"all":         {install.PanelUnit, install.BrokerUnit, install.RenewalService, install.UpdateService, release.RunUnit},
	"certificate": {install.RenewalService},
	"update":      {install.UpdateService, release.RunUnit},
	"agent":       {install.AgentUnit, install.AgentBrokerUnit},
}

func (a *App) logs(ctx context.Context, args []string) error {
	unit := "panel"
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		unit, args = args[0], args[1:]
	}
	fs := a.flags("logs", "Show recent logs: panel (default), broker, certificate, update, agent or all.")
	follow := fs.Bool("follow", false, "Keep printing new lines (Ctrl+C stops)")
	fs.BoolVar(follow, "f", false, "alias of --follow")
	lines := fs.Int("lines", 80, "Number of recent lines")
	fs.IntVar(lines, "n", 80, "alias of --lines")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	units, ok := logUnits[unit]
	if !ok || fs.NArg() != 0 {
		return errors.New("usage: gtm logs [panel|broker|certificate|update|agent|all] [-f] [-n LINES]")
	}
	if *lines < 1 || *lines > 10000 {
		return errors.New("--lines must be 1–10000")
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	cmd := []string{"--no-pager", "-n", strconv.Itoa(*lines)}
	for _, u := range units {
		cmd = append(cmd, "-u", u)
	}
	if *follow {
		cmd = append(cmd, "-f")
	}
	return a.Installer.Host.Stream(ctx, "journalctl", cmd...)
}

// twoFactor is the recovery path for two-factor sign-in; turning it on
// happens in the panel, where the QR code can be scanned.
func (a *App) twoFactor(ctx context.Context, args []string) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		a.UI.Header("gtm 2fa", "", "Two-factor sign-in is turned on in the panel: Settings › Security.")
		a.UI.Blank()
		a.UI.Rows([]tui.Row{{Label: "off", Value: "Turn it off (lost phone and recovery codes); signs out every session"}})
		a.UI.Blank()
		return nil
	}
	fs := a.flags("2fa off", "Turn two-factor sign-in off. Every signed-in session is signed out.")
	yes := fs.Bool("yes", false, "Do not ask for confirmation")
	fs.BoolVar(yes, "y", false, "alias of --yes")
	if args[0] != "off" {
		return errors.New("usage: gtm 2fa off [--yes]")
	}
	if e := a.parse(fs, args[1:]); e != nil {
		return e
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	if !*yes && (a.UI.Interactive || a.UI.Accessible) {
		proceed := false
		if e := a.UI.Confirm("Turn two-factor sign-in off?", "The password alone will sign in. Turn it on again in Settings › Security.", &proceed); e != nil {
			return e
		}
		if !proceed {
			return nil
		}
	}
	changed, e := a.Installer.DisableTwoFactor(ctx)
	if e != nil {
		return e
	}
	if !changed {
		a.UI.Done("Two-factor sign-in is already off")
	}
	a.UI.Blank()
	return nil
}
