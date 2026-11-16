package gtm

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

func (a *App) agent(ctx context.Context, args []string) error {
	sub := ""
	if len(args) > 0 {
		sub, args = args[0], args[1:]
	}
	switch sub {
	case "install":
		fs := a.flags("agent install", "Install or update an outbound Agent that reports to another server's panel.")
		var o install.AgentOptions
		fs.BoolVar(&o.Operations, "operations", false, "Allow leased GRE/FRP creation from the Controller")
		fs.BoolVar(&o.Traffic, "traffic", false, "Allow optional read-only traffic summaries")
		source := fs.String("source", "", "Unpacked release directory (set by install.sh)")
		if e := a.parse(fs, args); e != nil {
			return e
		}
		if e := a.requireRoot(); e != nil {
			return e
		}
		pkg, e := a.agentPackage(ctx, *source)
		if e != nil {
			return e
		}
		if pkg.Dir != "" && *source == "" {
			defer os.RemoveAll(pkg.Dir)
		}
		return a.installAgent(ctx, pkg, o)
	case "remove":
		return a.removeAgent(ctx, args)
	case "status", "":
		return a.status(ctx, args)
	}
	return fmt.Errorf("unknown agent command %q; use install, remove or status", sub)
}

// agentPackage uses the given directory, or downloads this release when the
// host has no installed files to reuse (a first Agent install via gtm).
func (a *App) agentPackage(ctx context.Context, dir string) (release.Package, error) {
	if dir != "" {
		return release.Local(dir)
	}
	if p, ok := a.Installer.InstalledPackage(); ok {
		return p, nil
	}
	arch, e := release.Arch()
	if e != nil {
		return release.Package{}, e
	}
	tmp, e := os.MkdirTemp("", "gtm-agent-*")
	if e != nil {
		return release.Package{}, e
	}
	a.UI.Step("Downloading v%s", a.Version)
	p, e := a.Release.Fetch(ctx, a.Version, arch, "", tmp)
	if e != nil {
		os.RemoveAll(tmp)
	}
	return p, e
}

func (a *App) installAgent(ctx context.Context, pkg release.Package, o install.AgentOptions) error {
	a.UI.Header("GRE Tunnel Manager", "v"+a.Version, "Outbound Agent · no public listener, no tunnel changes")
	a.UI.Blank()
	final, e := a.Installer.InstallAgent(ctx, pkg, o)
	if e != nil {
		return e
	}
	rows := []tui.Row{{Label: "Agent", Value: "running", Tone: tui.Good}}
	opt := func(on bool) (string, tui.Tone) {
		if on {
			return "allowed", tui.Good
		}
		return "off", tui.Quiet
	}
	v, t := opt(final.Operations)
	rows = append(rows, tui.Row{Label: "Paired setup", Value: v, Tone: t})
	v, t = opt(final.Traffic)
	rows = append(rows, tui.Row{Label: "Traffic", Value: v, Tone: t})
	notes := []string{"Check it with: sudo gtm status"}
	if final.Traffic {
		notes = append(notes, "Start traffic collection with: sudo gtm-panel nodes traffic --enable --interval 60")
	}
	a.UI.Card("Agent ready", rows, notes...)
	a.UI.Blank()
	return nil
}

func (a *App) removeAgent(ctx context.Context, args []string) error {
	fs := a.flags("agent remove", "Remove the Agent and its identity. Tunnels keep running.")
	yes := fs.Bool("yes", false, "Do not ask for confirmation")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	if e := a.Installer.CheckAgentRemoval(); errors.Is(e, install.ErrNotInstalled) {
		a.UI.Done("No Agent is installed")
		return nil
	} else if e != nil {
		return e
	}
	if e := a.confirmRemoval("Remove the Agent",
		[]tui.Row{{Label: "Removes", Value: "Agent services and its identity"}, {Label: "Keeps", Value: "tunnels, forwards and engines", Tone: tui.Quiet}},
		"Revoke this Node in the Controller's panel afterwards.", *yes); e != nil {
		return e
	}
	return a.Installer.RemoveAgent(ctx)
}

func (a *App) controller(ctx context.Context, args []string) error {
	if len(args) > 0 && args[0] == "enable" {
		args = args[1:]
	}
	fs := a.flags("controller enable", "Let Agents on other servers connect to this panel over a dedicated HTTPS port.")
	url := fs.String("url", "", "Address Agents use, for example https://203.0.113.10:9443")
	listen := fs.String("listen", "0.0.0.0:9443", "Local address of the Agent listener")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	if *url == "" {
		if !a.UI.Interactive && !a.UI.Accessible {
			return errors.New("--url is required, for example https://203.0.113.10:9443")
		}
		s := a.Installer.ReadStatus(ctx)
		host := "203.0.113.10"
		if s.Certificate != nil && s.Certificate.Host != "" {
			host = s.Certificate.Host
		}
		value := "https://" + host + ":9443"
		if e := a.UI.Input("Controller address", "Agents connect here. Open this TCP port in the firewall.", value, &value, nil); e != nil {
			return e
		}
		*url = value
	}
	return a.Installer.EnableController(ctx, *url, *listen)
}

// confirmRemoval shows what goes and what stays, then asks the operator to
// type REMOVE. --yes skips the question for automation.
func (a *App) confirmRemoval(title string, rows []tui.Row, note string, yes bool) error {
	a.UI.Card(title, rows, note)
	a.UI.Blank()
	if yes {
		return nil
	}
	if !a.UI.Interactive && !a.UI.Accessible {
		return errors.New("confirmation needed; run in a terminal or pass --yes")
	}
	answer := ""
	if e := a.UI.Input("Type REMOVE to continue", "Anything else cancels.", "REMOVE", &answer, nil); e != nil {
		return e
	}
	if answer != "REMOVE" {
		return tui.ErrCancelled
	}
	return nil
}
