package gtm

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/certificates"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

func (a *App) status(ctx context.Context, args []string) error {
	fs := a.flags("status", "Services, address, certificate and updates. Changes nothing.")
	asJSON := fs.Bool("json", false, "Print machine-readable JSON")
	if e := a.parse(fs, args); e != nil {
		return e
	}
	if e := a.requireRoot(); e != nil {
		return e
	}
	s := a.Installer.ReadStatus(ctx)
	if *asJSON {
		enc := json.NewEncoder(a.UI.Out())
		enc.SetIndent("", "  ")
		return enc.Encode(s)
	}
	a.UI.Header("GRE Tunnel Manager", "v"+a.Version, "")
	a.UI.Rows(a.statusRows(s, time.Now()))
	a.UI.Blank()
	return nil
}

// statusRows is the summary shown by gtm status and above the menu.
func (a *App) statusRows(s install.Status, now time.Time) []tui.Row {
	var rows []tui.Row
	if !s.Panel && !s.Agent {
		return []tui.Row{{Label: "Panel", Value: "not installed", Tone: tui.Quiet}}
	}
	if s.Panel {
		rows = append(rows, tui.Row{Label: "Panel", Value: s.PanelState, Tone: serviceTone(s.PanelState)})
		if s.BrokerState != "active" {
			rows = append(rows, tui.Row{Label: "Broker", Value: s.BrokerState, Tone: tui.Bad})
		}
		if s.ConfigError != "" {
			rows = append(rows, tui.Row{Label: "Config", Value: s.ConfigError, Tone: tui.Bad})
		} else {
			rows = append(rows, tui.Row{Label: "Address", Value: s.URL}, tui.Row{Label: "Login", Value: loginValue(s), Tone: tui.Quiet})
		}
		if s.Certificate != nil {
			rows = append(rows, certificateRow(*s.Certificate, now))
		}
		if s.Controller {
			rows = append(rows, tui.Row{Label: "Nodes", Value: "Controller on", Tone: tui.Good})
		}
	}
	if s.Agent {
		rows = append(rows, tui.Row{Label: "Agent", Value: s.AgentState, Tone: serviceTone(s.AgentState)})
	}
	rows = append(rows, updateRow(s, a.Version))
	return rows
}

func serviceTone(state string) tui.Tone {
	switch state {
	case "active":
		return tui.Good
	case "activating", "reloading":
		return tui.Warning
	}
	return tui.Bad
}

func days(d time.Duration) string {
	n := int(math.Ceil(d.Hours() / 24))
	switch {
	case n <= 0:
		return "today"
	case n == 1:
		return "in 1 day"
	}
	return fmt.Sprintf("in %d days", n)
}

func certificateRow(c certificates.Status, now time.Time) tui.Row {
	row := tui.Row{Label: "HTTPS"}
	r := c.Renewal
	switch {
	case c.Protocol == "http":
		row.Value, row.Tone = "off · gtm https issue enables it", tui.Warning
	case c.NotAfter.IsZero():
		row.Value, row.Tone = "certificate unreadable: "+c.LastError, tui.Bad
	case r != nil && r.AutoRenew && r.LastError != "":
		row.Value, row.Tone = "Let's Encrypt · renewal failing · gtm logs certificate", tui.Bad
	case r != nil && r.AutoRenew:
		row.Value, row.Tone = "Let's Encrypt · renews "+days(r.RenewAfter.Sub(now)), tui.Good
		if r.Staging {
			row.Value += " · staging"
		}
	case c.SelfSigned:
		row.Value, row.Tone = "self-signed · gtm https issue for a trusted one", tui.Warning
	case c.NotAfter.Sub(now) < 14*24*time.Hour:
		row.Value, row.Tone = "trusted · expires "+days(c.NotAfter.Sub(now)), tui.Warning
	default:
		row.Value, row.Tone = "trusted · expires "+days(c.NotAfter.Sub(now)), tui.Good
	}
	return row
}

func updateRow(s install.Status, current string) tui.Row {
	u := s.Update
	u.Current = current
	switch {
	case u.Available():
		return tui.Row{Label: "Update", Value: "v" + u.Latest + " available · gtm update", Tone: tui.Warning}
	case !u.Checked.IsZero() && u.Error == "":
		return tui.Row{Label: "Update", Value: "up to date · checked " + u.Checked.Local().Format("2006-01-02"), Tone: tui.Quiet}
	case !s.UpdateCheck && s.Panel:
		return tui.Row{Label: "Update", Value: "daily check off · gtm update --check", Tone: tui.Quiet}
	}
	return tui.Row{Label: "Update", Value: "not checked yet · gtm update --check", Tone: tui.Quiet}
}

// home shows the status and a menu of common tasks until the operator quits.
func (a *App) home(ctx context.Context, args []string) error {
	if e := a.requireRoot(); e != nil {
		return e
	}
	if !a.UI.Interactive && !a.UI.Accessible {
		return a.status(ctx, nil)
	}
	for {
		s := a.Installer.ReadStatus(ctx)
		a.UI.Header("GRE Tunnel Manager", "v"+a.Version, "")
		a.UI.Rows(a.statusRows(s, time.Now()))
		a.UI.Blank()
		actions := menuFor(s, a.Version)
		choice := actions[0].Value
		if e := tui.Select(a.UI, "What would you like to do?", "", actions, &choice); e != nil {
			return e
		}
		if choice == "quit" {
			return nil
		}
		e := a.Main(ctx, menuCommands[choice])
		if e != nil {
			a.UI.Fail(e)
		}
		if choice == "remove" || choice == "agent-remove" {
			if !a.Installer.PanelInstalled() && !a.Installer.AgentInstalled() {
				return nil
			}
		}
	}
}

var menuCommands = map[string][]string{
	"update":       {"update"},
	"check":        {"update", "--check"},
	"https":        {"https"},
	"port":         {"port"},
	"password":     {"password"},
	"logs":         {"logs", "--lines", "40"},
	"controller":   {"controller"},
	"repair":       {"install"},
	"remove":       {"remove"},
	"install":      {"install"},
	"agent":        {"install", "--agent"},
	"agent-logs":   {"logs", "agent", "--lines", "40"},
	"agent-remove": {"agent", "remove"},
}

func menuFor(s install.Status, current string) []tui.Choice[string] {
	s.Update.Current = current
	update := tui.Choice[string]{Label: "Check for updates", Value: "check"}
	if s.Update.Available() {
		update = tui.Choice[string]{Label: "Update to v" + s.Update.Latest, Value: "update"}
	}
	switch {
	case s.Panel:
		items := []tui.Choice[string]{
			update,
			{Label: "HTTPS certificate", Value: "https"},
			{Label: "Change port", Value: "port"},
			{Label: "Change password", Value: "password"},
			{Label: "Recent logs", Value: "logs"},
		}
		if !s.Controller {
			items = append(items, tui.Choice[string]{Label: "Manage other servers (Controller)", Value: "controller"})
		}
		return append(items,
			tui.Choice[string]{Label: "Repair installation", Value: "repair"},
			tui.Choice[string]{Label: "Remove panel", Value: "remove"},
			tui.Choice[string]{Label: "Quit", Value: "quit"})
	case s.Agent:
		return []tui.Choice[string]{
			update,
			{Label: "Recent Agent logs", Value: "agent-logs"},
			{Label: "Remove Agent", Value: "agent-remove"},
			{Label: "Quit", Value: "quit"},
		}
	}
	return []tui.Choice[string]{
		{Label: "Install the web panel", Value: "install"},
		{Label: "Install an Agent for another panel", Value: "agent"},
		{Label: "Quit", Value: "quit"},
	}
}

func loginValue(s install.Status) string {
	if s.TwoFactor {
		return s.Username + " · two-factor on"
	}
	return s.Username
}
