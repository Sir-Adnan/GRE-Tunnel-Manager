package main

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/control"
	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/nodes"
)

func retirePanel(ctx context.Context) error {
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return errors.New("panel retirement requires Linux root")
	}
	if len(os.Args) != 2 {
		return errors.New("uninstall-prepare accepts no arguments")
	}
	if _, e := os.Lstat(nodes.DefaultControllerDir); e == nil {
		// Do not leave a new root-owned lock blocking grepanel if preparation
		// later refuses and the installer restarts the previous service.
		lockPath := filepath.Join(nodes.DefaultControllerDir, "controller.lock")
		if _, e := os.Lstat(lockPath); os.IsNotExist(e) {
			defer os.Remove(lockPath)
		} else if e != nil {
			return e
		}
		h, e := nodes.Open(nodes.DefaultControllerDir)
		if e != nil {
			return e
		}
		defer h.Close()
		if e = h.CheckRetirement(); e != nil {
			return e
		}
	} else if !os.IsNotExist(e) {
		return e
	}
	x := &control.NodeExecutor{Directory: "/var/lib/gre-manager-node-operations"}
	if e := x.CheckRetirement(); e != nil {
		return e
	}
	i, e := os.Lstat("/var/lib/gre-manager-panel/metrics.json")
	if e == nil && !i.Mode().IsRegular() {
		return errors.New("accounting path is not a regular file")
	}
	if e != nil && !os.IsNotExist(e) {
		return e
	}
	if os.IsNotExist(e) {
		// nft is optional if accounting was never configured. Still clean an
		// orphaned table when it is available.
		if _, e := exec.LookPath("nft"); e != nil {
			return nil
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return control.RetireMetrics(ctx, control.Executor{})
}
