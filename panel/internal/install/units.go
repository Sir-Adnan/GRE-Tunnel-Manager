package install

import (
	"os"
	"strings"
)

// Unit names owned by the installer.
const (
	PanelUnit       = "gre-manager-panel.service"
	BrokerUnit      = "gre-manager-panel-broker.service"
	RenewalService  = "gre-manager-panel-certificate.service"
	RenewalTimer    = "gre-manager-panel-certificate.timer"
	UpdateService   = "gre-manager-panel-update-check.service"
	UpdateTimer     = "gre-manager-panel-update-check.timer"
	AgentUnit       = "gre-manager-agent.service"
	AgentBrokerUnit = "gre-manager-agent-broker.service"
)

// panelUnits are written on every install or update, in this order.
var panelUnits = []struct{ name, body string }{
	{BrokerUnit, brokerBody},
	{PanelUnit, panelBody},
	{RenewalService, renewalServiceBody},
	{RenewalTimer, renewalTimerBody},
	{UpdateService, updateServiceBody},
	{UpdateTimer, updateTimerBody},
}

const brokerBody = `[Unit]
Description=GRE Manager private control broker
After=network-online.target
# Traffic sampling and opt-in quota guards run here. They must keep working
# while the public panel is stopped, restarting or crash-looping.
StopWhenUnneeded=no
[Service]
Type=simple
User=root
Group=grepanel
RuntimeDirectory=gre-manager-panel
RuntimeDirectoryMode=0750
UMask=0077
ExecStart=/usr/local/bin/gtm-panel broker
Restart=on-failure
RestartSec=3
TimeoutStopSec=12min
KillMode=mixed
Environment=GOMEMLIMIT=64MiB
ProtectHome=yes
PrivateTmp=yes
[Install]
WantedBy=multi-user.target
`

const panelBody = `[Unit]
Description=GRE Tunnel Manager Web Panel
Requires=gre-manager-panel-broker.service
After=gre-manager-panel-broker.service network-online.target
[Service]
Type=simple
User=grepanel
Group=grepanel
UMask=0077
ExecStart=/usr/local/bin/gtm-panel serve
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=3
Environment=GOMEMLIMIT=64MiB
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
[Install]
WantedBy=multi-user.target
`

// Renewal is a no-op until "gtm-panel certificate issue" saves a recipe.
const renewalServiceBody = `[Unit]
Description=GRE Tunnel Manager panel certificate renewal
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/gre-manager-panel/acme/settings.json
[Service]
Type=oneshot
ExecStart=/usr/local/bin/gtm-panel certificate renew
TimeoutStartSec=10min
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
`

const renewalTimerBody = `[Unit]
Description=Renew the GRE Tunnel Manager panel certificate when due
[Timer]
OnCalendar=*-*-* 00/6:00:00
RandomizedDelaySec=45min
Persistent=true
[Install]
WantedBy=timers.target
`

// The check only reads the public release number; installing stays manual.
const updateServiceBody = `[Unit]
Description=Check for a newer GRE Tunnel Manager release
After=network-online.target
Wants=network-online.target
ConditionPathExists=/etc/gre-manager-panel/config.json
[Service]
Type=oneshot
ExecStart=/usr/local/bin/gtm-panel update-check
TimeoutStartSec=2min
NoNewPrivileges=yes
ProtectHome=yes
PrivateTmp=yes
`

const updateTimerBody = `[Unit]
Description=Daily check for a newer GRE Tunnel Manager release
[Timer]
OnCalendar=daily
RandomizedDelaySec=4h
Persistent=true
[Install]
WantedBy=timers.target
`

// AgentOptions are the explicit opt-ins of an outbound Agent.
type AgentOptions struct {
	Operations bool // leased paired GRE/FRP creation
	Traffic    bool // optional local accounting and read-only summaries
}

func agentBrokerBody(o AgentOptions) string {
	flags := "--read-only"
	if o.Operations {
		flags += " --node-operations"
	}
	if o.Traffic {
		flags += " --agent-traffic"
	}
	var b strings.Builder
	b.WriteString("[Unit]\nDescription=GRE Manager local read-only Agent broker\nAfter=network-online.target\n")
	if o.Operations {
		b.WriteString("StopWhenUnneeded=no\n")
	} else {
		b.WriteString("StopWhenUnneeded=yes\n")
	}
	b.WriteString("[Service]\nUser=root\nGroup=greagent\nRuntimeDirectory=gre-manager-agent\nRuntimeDirectoryMode=0750\nUMask=0077\n")
	b.WriteString("ExecStart=/usr/local/bin/gtm-panel broker " + flags + " --socket /run/gre-manager-agent/broker.sock\n")
	b.WriteString("Restart=on-failure\nRestartSec=5\nEnvironment=GOMEMLIMIT=64MiB\nProtectHome=yes\nPrivateTmp=yes\n")
	if o.Operations {
		// The root worker recovers unconfirmed leases even without the Agent.
		b.WriteString("TimeoutStopSec=12min\n\n[Install]\nWantedBy=multi-user.target\n")
	}
	return b.String()
}

func agentBody(o AgentOptions) string {
	exec := "/usr/local/bin/gtm-panel nodes agent"
	if o.Operations {
		exec += " --operations"
	}
	if o.Traffic {
		exec += " --traffic"
	}
	return `[Unit]
Description=GRE Manager outbound inventory Agent
Requires=gre-manager-agent-broker.service
After=gre-manager-agent-broker.service network-online.target
[Service]
User=greagent
Group=greagent
UMask=0077
ExecStart=` + exec + `
Restart=on-failure
RestartSec=30
RestartPreventExitStatus=1
Environment=GOMEMLIMIT=64MiB
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/gre-manager-agent
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
CapabilityBoundingSet=
[Install]
WantedBy=multi-user.target
`
}

// installedAgentOptions keeps explicit opt-ins across upgrades. The recovery
// worker is never removed silently while it may own an unconfirmed lease.
func installedAgentOptions(l Layout) AgentOptions {
	data, e := os.ReadFile(l.Unit(AgentUnit))
	if e != nil {
		return AgentOptions{}
	}
	var o AgentOptions
	for _, line := range strings.Split(string(data), "\n") {
		rest, ok := strings.CutPrefix(line, "ExecStart=/usr/local/bin/gtm-panel nodes agent")
		if !ok {
			continue
		}
		for _, flag := range strings.Fields(rest) {
			switch flag {
			case "--operations":
				o.Operations = true
			case "--traffic":
				o.Traffic = true
			default:
				return AgentOptions{}
			}
		}
	}
	return o
}

func writeUnit(l Layout, name, body string) error {
	return writeFileAtomic(l.Unit(name), []byte(body), 0644)
}
