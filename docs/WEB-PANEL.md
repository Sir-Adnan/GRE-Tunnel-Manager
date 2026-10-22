# GRE Tunnel Manager web panel

The optional Go panel manages connections on its own host. The interface supports Persian RTL and English LTR, desktop/mobile layouts, the original Nettinx palette and the Neutral alternative. Tunnel traffic does not pass through the panel. Stopping the panel does not stop independently managed tunnels.

The [development roadmap](ROADMAP.md) distinguishes current local-host capabilities from planned Node/Agent management. The unreleased Phase 1 interface changes below are not automatically installed by the published v1.3.0 package.

## Installation and login

On Debian/Ubuntu with systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh -o panel-install.sh && sudo bash panel-install.sh
```

Terminal menu **8 · Web Panel** uses the same installer. It downloads a versioned release archive and matching checksum. The package contains the Go executable, embedded built interface and matching Bash helper. Managed servers do not require Node, a Go compiler, Docker or a database server.

1. Enter the public server IP for the HTTPS certificate.
2. Choose a listen address; `0.0.0.0` listens on all IPv4 addresses, `::` selects IPv6.
3. Enter a port, or leave it blank to choose and persist an available random port.
4. Create an administrator username and a hidden, confirmed 12–72-byte password.
5. Allow the chosen TCP port in host/provider firewalls and open `https://SERVER_IP:PORT`.

Random ports do not replace authentication. The initial certificate is self-signed. Verify its printed SHA-256 fingerprint through SSH before trusting it. To use a CA certificate, edit `certificate` and `private_key` in the configuration, retain restricted `root:grepanel` key access and restart. Automatic ACME issuance/renewal is not implemented.

Current production installation is HTTPS-only. Explicit HTTP, quick installation, optional IP discovery and eight-character user passwords are scheduled for Phase 2; they are not available merely because they appear in the roadmap. The loopback-only demonstration uses HTTP and cannot authenticate against a production installation.

```bash
sudo gtm-panel address
sudo systemctl status gre-manager-panel --no-pager
sudo gtm-panel reset-password
sudo systemctl restart gre-manager-panel
sudo systemctl stop gre-manager-panel gre-manager-panel-broker
sudo systemctl start gre-manager-panel
```

Restart after password reset to revoke existing in-memory sessions. Change `listen` in `/etc/gre-manager-panel/config.json` and restart to change ports. Reinstallation preserves existing port, credentials and certificate. The panel is enabled at boot; temporary stop and disabling boot startup are different actions.

## Supported adapters

| Area | Supported operations |
| --- | --- |
| Forward/relay management | Multi-port creation, individual edits, bulk selection, enable/disable/delete and review before application |
| iptables/nftables | IPv4/IPv6, TCP/UDP/both, DNAT, destination-port mapping, masquerade/preserve source, interface selection and weighted distribution |
| HAProxy | TCP, weighted targets, round robin/leastconn/source/failover, 13 bounded timeout/queue/maxconn/check/slow-start/PROXY/log options and balanced/VPN/lean presets |
| Realm | TCP/UDP/both, weighted targets, round robin/iphash, timeouts, keepalive/probes, incoming/outgoing PROXY metadata and log level |
| GRE | GRE/ip6gre creation with ID, role, local/peer IP and MTU; service state/actions/logs and dependency-aware deletion |
| FRP | Entrance/destination, TCP/UDP services, TCP/WS/WSS/QUIC transports, stream multiplexing and TCP balancing groups |
| rathole | Entrance/destination, TCP/UDP/both, Noise NK, entrance key creation and public-key pinning at destination |
| Engine installation | Install optional engines selectively or together without creating tunnels |

This is a bounded adapter set, not a complete editor for every native engine feature. Arbitrary config/file editing, HAProxy HTTP/ACL/TLS routing, native encrypted Realm transports, MPTCP, hostname destinations and multi-server orchestration are not currently exposed. Capabilities advertised by the API and forms define supported behavior. FRP and rathole provide the currently exposed encrypted transports.

Presets initialize settings; they do not guarantee throughput or resource usage on every route. PROXY metadata requires a compatible receiver. Preserved source IP requires correct return routing. A kernel forward marked configured does not prove peer reachability; an active relay process does not prove end-to-end tunnel health.

Configure GRE/reverse peers independently on each host today. The GRE web form does not add watchdogs or global firewall/sysctl changes. Protocol 47 must be allowed by the network. GRE IDs/roles preserve the existing keyed wire contract. GRE/reverse configuration is outside forwarding restore points.

## Interface corrections in Phase 1

The interface remains on Radix/shadcn; Base UI examples are references, not a second installed primitive system. Switches/checkboxes use Radix `data-state` styling, with visible checked states, partial selection, keyboard controls and labels. Dedicated HAProxy/Realm creation pages retain their engine. Optional forward/relay names are available in the normal form; empty names use the existing automatic default. Names still follow backend ASCII/length validation. Independent GRE/reverse display names require the later metadata work in Phase 5.

The header exposes light/dark/system controls. The official shadcn sidebar composition handles desktop collapse and mobile navigation. Application typography uses locally served Vazirmatn; display numbers follow locale, while IPs, ports and code retain readable LTR isolation. Forms use mobile input sizing and reachable action footers. Action tooltips support hover/focus; question-mark help also opens on click/tap.

Traffic settings, usage and charts occupy separate full-width sections. Changes remain drafts until **Save & apply** completes. The collection badge reflects saved state rather than the draft switch. Failed reads/applies remain visible. Selecting a subset requires at least one resource when enabling, because an empty API selection means all resources.

A connection's ID, engine and accounting source are different concepts. For example, `F000003` is a managed record ID; `HAProxy` is its relay engine; `nftables` may be its accounting mechanism. The interface shows the engine beside its name and explains the ID/accounting mechanism in contextual help.

## Optional traffic accounting

Collection defaults to off. Enabling creates separate `inet gtm_panel_metrics` counters and periodic sampling. No global ruleset is flushed and no forwarding/blocking verdict is added. Port accounting requires nftables even when the forwarding engine is iptables. Disabling removes the owned accounting table and stops periodic sampling while retaining stored totals. A lightweight enabled-state timer remains in the broker.

- Kernel forwards use forward-hook accounting and conntrack original/reply directions, not NAT-chain counters as a measure of the complete flow.
- HAProxy/Realm account the user-facing entrance leg in input/output. Their second outgoing relay connection is not counted again.
- Reverse accounting measures public entrance service ports. Per-service destination volume is not inferred from multiplexed control-channel bytes.
- GRE uses interface rx/tx counters. The same traffic may appear in GRE and forward views; these totals are never summed into an overall total.

These are network-layer bytes, not application payload or provider billing. NOTRACK, bypassing offloads, DNAT to the local host and custom/asymmetric routing can fall outside coverage. Select all or particular supported resources and an interval from 15–3600 seconds, default 60.

Counters/totals are checkpointed and decreasing raw counters are treated as resets. Abrupt termination or deleting counters before the next sample can lose increments. This is not billing-grade accounting. Stopping the panel with accounting enabled leaves kernel counters installed; disable collection first to remove that overhead.

Phase 1 adds a lazily loaded shadcn/Recharts Area chart for each resource, using at most 60 distinct samples fetched during the current page visit. Refresh after a later sample to add a point; duplicate timestamps do not invent new points. Two actual samples are needed. Leaving the page clears this chart history; no browser persistence, cross-resource sum or persistent historical series is implied. Persistent optional history and retention are Phase 5 work. A chart is not an automatic background poller.

## Architecture and security

The public HTTPS service runs as restricted `grepanel`. Privileged operations go to a local root broker through a group-protected Unix socket. Requests are closed, typed operations; no arbitrary shell, argv or file API is exposed. Both Go and Bash validate inputs. Forward writes use the shared lock, complete-state reload, native preflight, snapshots and recovery. Per-row revisions reject stale updates/deletions.

Sessions live in memory for four hours with HttpOnly/Secure/SameSite cookies. Writes require exact Origin and CSRF validation. Login attempts, request/output sizes, sessions and jobs are bounded. Passwords use bcrypt and production has no default credentials. The loopback-only demo is explicitly simulated and cannot execute system commands. Sessions/jobs reset when the public process restarts; a broker-owned operation can finish independently, so refresh actual state after reconnecting.

| Module | Responsibility |
| --- | --- |
| `panel/internal/model` | Typed contracts, capability matrix, TSV validation/conversion |
| `panel/internal/control` | Local broker, Bash adapter, inventory and accounting |
| `panel/internal/auth` | Login, sessions and CSRF |
| `panel/internal/httpapi` | HTTP boundary and bounded asynchronous jobs |
| `panel/web/src/features` | Feature pages/forms, independent of theme choices |
| `panel/web/src/experience` | Appearance contract, selection, themes and direction |
| `src/api.sh`, `src/links.sh`, `src/reverse_api.sh` | Validated noninteractive local operations |

Existing TSV v1/v2 remain supported; advanced Realm options use v3. Older releases cannot load v3: downgrade requires a suitable older snapshot. The terminal keeps its fixed English interface.

## Appearance fidelity and limits

The original Nettinx colors are preserved by explicit user choice. White primary-button text has approximately 2.5:1 contrast in light mode and 2.62:1 in dark mode; some sidebar combinations also fail AA. These are recorded limitations, not a passed contrast gate. Neutral remains an alternative. The later explicit Vazirmatn font choice changes application typography without altering original palette source values.

Fonts are served locally, Persian letter-spacing is zero and technical values retain LTR isolation. Node, Vite and TypeScript are build-time tools; the browser executes the built React JavaScript. Two Go processes run in production, plus whichever tunnel engines are enabled. `GOMEMLIMIT=64MiB` per Go process is a soft runtime memory setting, not a hard RSS cap or measurement of actual use.
