package main

import (
	"context"
	"errors"
	"os"
	"runtime"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/gtm"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/install"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/setup"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/tui"
)

// errReported marks an error the gtm interface already showed.
var errReported = errors.New("reported")

// runGTM is the gtm command (also reached as "gtm-panel gtm" and through the
// /usr/local/bin/gtm link to this executable).
func runGTM(ctx context.Context, args []string) error {
	ui := tui.New(os.Stdin, os.Stdout)
	defer ui.Settle()
	app := &gtm.App{
		UI: ui,
		Installer: &install.Installer{
			// Command output goes through the UI, which keeps it out of the
			// live progress area and shows it when a step fails.
			Host:       install.System{Stdin: os.Stdin, Stdout: ui.Log(), Stderr: ui.Log()},
			Report:     ui,
			Interfaces: install.LocalAddresses,
		},
		Release:  release.Default("gtm-panel/" + Version),
		Version:  Version,
		Root:     runtime.GOOS == "linux" && os.Geteuid() == 0,
		Getenv:   os.Getenv,
		Discover: setup.Discover,
	}
	if e := app.Main(ctx, args); e != nil {
		if errors.Is(e, gtm.ErrReported) {
			return errReported
		}
		ui.Fail(e)
		ui.Blank()
		return errReported
	}
	return nil
}
