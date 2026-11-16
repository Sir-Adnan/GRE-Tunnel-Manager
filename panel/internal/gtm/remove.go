package gtm

import (
	"context"
	"errors"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

func (a *App) remove(ctx context.Context, args []string) error {
	fs := a.flags("remove", "Remove the web panel. Tunnels, forwards, engines and firewall rules keep running.")
	yes := fs.Bool("yes", false, "Do not ask for confirmation")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	if e := a.Installer.CheckPanelRemoval(ctx); errors.Is(e, install.ErrNotInstalled) {
		a.UI.Done("The web panel is not installed")
		return nil
	} else if e != nil {
		return e
	}
	if e := a.confirmRemoval("Remove the web panel", []tui.Row{
		{Label: "Removes", Value: "panel services, login, certificates and renewal"},
		{Label: "", Value: "Controller identities, jobs, audit and traffic totals"},
		{Label: "Keeps", Value: "tunnels, forwards, engines and firewall policy", Tone: tui.Quiet},
	}, "Enrolled Agents must enroll again after a reinstall.", *yes); e != nil {
		return e
	}
	return a.Installer.RemovePanel(ctx)
}
