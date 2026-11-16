package install

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"

	"github.com/Sir-Adnan/GRE-Tunnel-Manager/panel/internal/release"
)

const (
	agentDir        = "/var/lib/gre-manager-agent"
	agentTrafficDir = "/var/lib/gre-manager-agent-traffic"
	operationsDir   = "/var/lib/gre-manager-node-operations"
	nodesDir        = "/var/lib/gre-manager-nodes"
	nodesDropIn     = UnitDir + "/gre-manager-panel.service.d/nodes.conf"
)

// InstallAgent installs or updates an outbound Agent. Existing identities and
// opt-ins are kept; options can only add opt-ins, never drop them silently.
func (in *Installer) InstallAgent(ctx context.Context, p release.Package, o AgentOptions) (AgentOptions, error) {
	r, l, h := in.report(), in.Layout, in.Host
	if regular(l.Unit(PanelUnit)) {
		return o, errors.New("this host runs the panel and is already its local Node; no Agent is needed")
	}
	if e := in.checkPackage(ctx, p); e != nil {
		return o, e
	}
	for _, tool := range []string{"systemctl", "runuser", "ip"} {
		if h.LookPath(tool) != nil {
			return o, fmt.Errorf("missing prerequisite: %s", tool)
		}
	}
	lock, e := h.Lock(l.Path(LockFile))
	if e != nil {
		return o, e
	}
	defer lock.Close()
	if v, e := h.Run(ctx, p.Binary, "nodes", "protocol"); e != nil || v != "1" {
		return o, errors.New("the package lacks Node protocol 1; use a matching release")
	}
	installed := installedAgentOptions(l)
	o.Operations = o.Operations || installed.Operations
	o.Traffic = o.Traffic || installed.Traffic
	if o.Operations {
		if v, e := h.Run(ctx, p.Binary, "nodes", "operations-version"); e != nil || v != "1" {
			return o, errors.New("the package lacks paired operation support")
		}
	}
	if o.Traffic {
		if v, e := h.Run(ctx, p.Binary, "nodes", "traffic-version"); e != nil || v != "1" {
			return o, errors.New("the package lacks traffic summary protocol 1")
		}
	}
	account, e := ensureAccount(ctx, h, "greagent")
	if e != nil {
		return o, e
	}
	if e = ensureDir(h, l.Path(agentDir), 0700, account.UID, account.GID); e != nil {
		return o, e
	}
	// The service account runs the verified binary for enrollment. The
	// package directory holds public release content only.
	if filepath.Dir(p.Binary) != filepath.Dir(l.Path(Binary)) {
		if e = os.Chmod(filepath.Dir(p.Binary), 0711); e != nil {
			return o, e
		}
	}
	if !regular(l.Path(agentDir + "/identity.json")) {
		settle(r)
		r.Note("Enrolling with the Controller: paste the one-time code from the panel")
		// The binary reads the invitation from the terminal with echo off.
		if e = h.Stream(ctx, "runuser", "-u", "greagent", "--", p.Binary, "nodes", "enroll"); e != nil {
			return o, fmt.Errorf("enrollment failed: %w", e)
		}
	}
	if e = h.Stream(ctx, "runuser", "-u", "greagent", "--", p.Binary, "nodes", "check"); e != nil {
		return o, fmt.Errorf("the Agent identity is not usable; nothing was stopped: %w", e)
	}
	previous, e := in.snapshot()
	if e != nil {
		return o, e
	}
	defer previous.discard()
	units := []string{AgentBrokerUnit, AgentUnit}
	if e = in.deploy(ctx, p, units); e != nil {
		in.rollback(ctx, previous, units)
		return o, e
	}
	in.installShims()
	if e = writeUnit(l, AgentBrokerUnit, agentBrokerBody(o)); e == nil {
		e = writeUnit(l, AgentUnit, agentBody(o))
	}
	if e == nil && o.Traffic {
		e = ensureDir(h, l.Path(agentTrafficDir), 0700, 0, 0)
	}
	if e != nil {
		return o, e
	}
	steps := [][]string{{"daemon-reload"}}
	if o.Operations {
		steps = append(steps, []string{"enable", "--now", AgentBrokerUnit})
	}
	steps = append(steps, []string{"enable", "--now", AgentUnit}, []string{"is-active", "--quiet", AgentUnit})
	for _, args := range steps {
		if _, e = h.Run(ctx, "systemctl", args...); e != nil {
			_ = h.Stream(ctx, "journalctl", "-u", AgentUnit, "-n", "20", "--no-pager")
			if in.rollback(ctx, previous, units) {
				return o, fmt.Errorf("the new Agent did not start; the previous release was restored: %w", e)
			}
			return o, fmt.Errorf("the Agent did not start: %w", e)
		}
	}
	r.Done("Agent is running")
	return o, nil
}

var agentIdentityName = regexp.MustCompile(`^identity(\.[a-z0-9-]{1,40})?\.json$`)

// checkAgentManifest refuses removal while unknown files or pending paired
// operations exist. An unconfirmed lease needs the root recovery worker.
func (in *Installer) checkAgentManifest() error {
	l := in.Layout
	check := func(dir string, owned func(string) bool) error {
		entries, e := os.ReadDir(l.Path(dir))
		if errors.Is(e, os.ErrNotExist) {
			return nil
		}
		if info, le := os.Lstat(l.Path(dir)); le != nil || !info.IsDir() {
			return fmt.Errorf("unsafe Agent directory: %s", dir)
		}
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if !entry.Type().IsRegular() || !owned(entry.Name()) {
				return fmt.Errorf("unrecognized Agent file; inspect it before removal: %s/%s", dir, entry.Name())
			}
		}
		return nil
	}
	if e := check(agentDir, func(n string) bool { return agentIdentityName.MatchString(n) || tempWrite.MatchString(n) }); e != nil {
		return e
	}
	if e := check(agentTrafficDir, func(n string) bool { return n == "metrics.json" || tempWrite.MatchString(n) }); e != nil {
		return e
	}
	return check(operationsDir, func(n string) bool {
		if leaseName.MatchString(n) {
			return false
		}
		return n == "broker.lock"
	})
}

// CheckAgentRemoval runs every refusal check without changing anything.
func (in *Installer) CheckAgentRemoval() error {
	if !in.AgentInstalled() {
		return ErrNotInstalled
	}
	if e := in.checkAgentManifest(); e != nil {
		return fmt.Errorf("%w (a pending paired operation must finish or expire first)", e)
	}
	return nil
}

// RemoveAgent removes the Agent and its identity. Tunnels stay in place.
func (in *Installer) RemoveAgent(ctx context.Context) error {
	r, l, h := in.report(), in.Layout, in.Host
	lock, e := h.Lock(l.Path(LockFile))
	if e != nil {
		return e
	}
	defer lock.Close()
	if e = in.CheckAgentRemoval(); e != nil {
		return e
	}
	r.Step("Stopping the Agent")
	for _, unit := range []string{AgentUnit, AgentBrokerUnit} {
		if regular(l.Unit(unit)) {
			if _, e = h.Run(ctx, "systemctl", "disable", "--now", unit); e != nil {
				return e
			}
		}
	}
	for _, unit := range []string{AgentUnit, AgentBrokerUnit} {
		if e = removeFile(l.Unit(unit)); e != nil {
			return e
		}
	}
	for _, dir := range []string{agentDir, agentTrafficDir, operationsDir} {
		entries, e := os.ReadDir(l.Path(dir))
		if errors.Is(e, os.ErrNotExist) {
			continue
		}
		if e != nil {
			return e
		}
		for _, entry := range entries {
			if e = os.Remove(l.Path(dir + "/" + entry.Name())); e != nil {
				return e
			}
		}
		if e = os.Remove(l.Path(dir)); e != nil {
			return e
		}
	}
	if _, e = h.Run(ctx, "systemctl", "daemon-reload"); e != nil {
		return e
	}
	if !in.PanelInstalled() || !regular(l.Unit(PanelUnit)) {
		in.removeShared()
	}
	r.Done("Agent removed; tunnels keep running. Revoke its identity on the Controller")
	return nil
}

// EnableController turns on the panel's Agent listener. Existing identities
// and enrolled Nodes are kept.
func (in *Installer) EnableController(ctx context.Context, url, listen string) error {
	r, l, h := in.report(), in.Layout, in.Host
	if !regular(l.Path(ConfigFile)) || !regular(l.Path(Binary)) {
		return errors.New("install the panel first")
	}
	if url == "" {
		return errors.New("--url is required, for example https://203.0.113.10:9443")
	}
	if listen == "" {
		listen = "0.0.0.0:9443"
	}
	lock, e := h.Lock(l.Path(LockFile))
	if e != nil {
		return e
	}
	defer lock.Close()
	if v, e := h.Run(ctx, l.Path(Binary), "nodes", "protocol"); e != nil || v != "1" {
		return errors.New("the installed panel lacks Node protocol 1; run gtm update first")
	}
	account, e := lookupAccount(ctx, h, "grepanel")
	if e != nil {
		return e
	}
	if e = ensureDir(h, l.Path(nodesDir), 0700, account.UID, account.GID); e != nil {
		return e
	}
	if !regular(l.Path(nodesDir + "/controller.json")) {
		if e = h.Stream(ctx, "runuser", "-u", "grepanel", "--", l.Path(Binary), "nodes", "init", "--url", url, "--listen", listen); e != nil {
			return e
		}
	} else {
		r.Note("Existing Controller identity, address and enrolled Nodes are kept")
	}
	if e = h.Stream(ctx, "runuser", "-u", "grepanel", "--", l.Path(Binary), "nodes", "check-controller"); e != nil {
		return e
	}
	if e = os.MkdirAll(filepath.Dir(l.Path(nodesDropIn)), 0755); e != nil {
		return e
	}
	if e = writeFileAtomic(l.Path(nodesDropIn), []byte("[Service]\nReadWritePaths=/var/lib/gre-manager-nodes\n"), 0644); e != nil {
		return e
	}
	for _, args := range [][]string{{"daemon-reload"}, {"restart", PanelUnit}, {"is-active", "--quiet", PanelUnit}} {
		if _, e = h.Run(ctx, "systemctl", args...); e != nil {
			return e
		}
	}
	r.Done("Controller enabled; open its TCP port and add Nodes from the panel")
	return nil
}
