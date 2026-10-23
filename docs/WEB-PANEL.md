# GRE Tunnel Manager web panel

The optional Go panel manages connections on its own host. The interface supports Persian RTL and English LTR, desktop/mobile layouts, the original Nettinx palette and the Neutral alternative. Tunnel traffic does not pass through the panel. Stopping the panel does not stop independently managed tunnels.

The [development roadmap](ROADMAP.md) tracks local management, optional Nodes, leased paired operations and read-only remote traffic. Current source includes these completed milestones and the updated installation flow. The published v1.3.0 package still contains the earlier interface and HTTPS-only setup; pulling a newer installer does not rebuild that binary. See the release boundary below.

## Installation and login

Source now includes [engine/version details](ENGINE-CAPABILITIES.md), bounded HAProxy HTTP readiness and [guarded panel removal](PANEL-REMOVAL.md). These require a matching current source package until a new release is approved and published. General engine edits still act locally; remote writes are limited to the documented paired GRE/FRP workflow.

On Debian/Ubuntu with systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh -o panel-install.sh && sudo bash panel-install.sh
```

Terminal menu **8 · Web Panel** uses the same installer. It downloads a versioned release archive and matching checksum. The package contains the Go executable, embedded built interface and matching Bash helper. Managed servers do not require Node, a Go compiler, Docker or a database server.

### Published package versus current source

The default command above remains compatible with published v1.3.0: enter the public IP, listen IP, selected/random port, administrator username and a confirmed 12–72-byte password. It installs HTTPS with a self-signed IP certificate. New options are never silently ignored: asking an older package for `--quick`, `--protocol` or other new setup options on a fresh installation fails before stopping any service.

The following flow requires a package built from the updated source (`gtm-panel setup-version` prints `2`). It has not yet been published as a new release. Developers can build matching packages using [the development guide](DEVELOPMENT.md#optional-panel), then install explicitly:

```bash
sudo bash panel-install.sh --package-dir panel/bin --quick
```

### Quick and custom setup

With an updated package, ordinary installation offers **1 · Quick setup** or **2 · Custom setup**, followed by numbered HTTPS/HTTP selection. Quick setup detects the public IP, chooses an available random port and generates a strong 32-character password. It prints the URL, username and generated password once. Save that password; only its bcrypt hash is stored. Custom setup lets you choose the address, port, username and a hidden, confirmed password.

For a downloaded installer and an updated published package, the direct quick-install command is:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh -o panel-install.sh && sudo bash panel-install.sh --quick
```

Until that package is published, use `--package-dir` as above; the current published package will explicitly reject this quick command. No release/tag was replaced by the source changes.

| Option | Behavior for a fresh installation |
| --- | --- |
| `--quick` | No setup questions; HTTPS, automatic IP, random port and generated credentials by default |
| `--protocol https` / `--protocol http` | Choose the browser protocol explicitly; HTTPS is the default |
| `--address IP_OR_DOMAIN` | Reachable IPv4, IPv6 or ASCII domain, without a scheme, port or path; skips online IP discovery |
| `--port PORT` | Selected TCP port; omitted or `0` chooses an available random port |
| `--username USER` | Default `admin`; 3–40 ASCII letters, digits, dots, dashes or underscores |
| `--listen LOCAL_IP` | Local bind address; default all IPv4 addresses, or `::` for an explicitly supplied/detected IPv6 address |
| `--install-engines` | Optionally preinstall all supported engines without creating tunnels; default installs none |
| `--package-dir DIR` | Use a local matching archive and SHA256SUMS instead of downloading a release |

For example, after obtaining a compatible package:

```bash
sudo bash panel-install.sh --quick --protocol http --address 203.0.113.10 --port 8080
sudo bash panel-install.sh --quick --address panel.example.com --port 8443
```

HTTP works directly on the server IP without a certificate. Its login and management traffic are unencrypted; the login page and connection help identify this. Sessions still require authentication, HttpOnly/SameSite cookies, Origin and CSRF checks. HTTPS additionally sets the Secure cookie flag. Separate HTTP/HTTPS cookie names prevent an old Secure cookie from blocking a later HTTP login on the same host. Do not enable `Secure` on a plain HTTP listener: browsers would not send its cookie. This browser setting does not weaken the Agent control channel, which remains authenticated and encrypted.

User-chosen passwords require at least **eight Unicode characters**, at most **72 UTF-8 bytes**, with no control characters. Hidden password entry permits up to three attempts for invalid or mismatched input. Eight non-ASCII characters can occupy more than eight bytes. Quick setup generates 24 cryptographically random bytes encoded as 32 URL-safe characters. Passwords are not accepted in command arguments, URLs or environment variables. The generated password is printed only by the foreground setup command, never by the services or `address` command. Treat that one-time output as a secret; avoid capturing it in shared terminal logs.

### Address discovery, certificates and access

When the address is omitted, setup tries bounded HTTPS requests to `api.ipify.org` and `api6.ipify.org` (six seconds overall, at most 128 response bytes accepted). This discovers the outgoing public IP, which can differ from the reachable entrance on NAT, proxy or multi-address hosts. Supplying `--address` avoids those requests. A failed quick discovery stops before writing a configuration; retry with an explicit address. Custom setup offers manual entry. Discovery creates no daemon or periodic task.

A domain must already resolve to the server. Setup does not register a domain, edit DNS or provision an arbitrary public hostname. Domain listeners default to IPv4; use `--listen ::` when IPv6 binding is needed. An IPv6 URL is printed with brackets. Opening host/provider firewalls remains an operator action; random ports do not replace authentication. The chosen port is checked against TCP sockets, but custom/manual DNAT rules and a race with another process after setup are not fully modeled. Service startup reports failure if it cannot bind.

HTTPS creates a self-signed certificate with the selected IP/domain SAN and local addresses. Verify its SHA-256 fingerprint through SSH before trusting it. A domain SAN does not make a self-signed certificate publicly trusted. To use an operator-managed CA certificate, set absolute `certificate` and `private_key` paths in the configuration, keep restricted `root:grepanel` access and restart. Automatic ACME issuance/renewal and trusted reverse-proxy/forwarded-header support are not implemented; protocol and Origin checks refer to the direct listener.

### Existing installations and recovery

Reinstallation preserves protocol, address, port, credentials and certificates, including operator certificates. Setup flags do not reconfigure an existing installation. Old configurations without `protocol` retain HTTPS; no credential migration is required. The incoming binary validates configuration before any service stop. A single installer lock prevents concurrent installs. Failed checksums, wrong binary versions, invalid existing config and failed initial setup stop before replacing the executable or stopping a working panel.

```bash
sudo gtm-panel address
sudo systemctl status gre-manager-panel --no-pager
sudo gtm-panel reset-password
sudo systemctl restart gre-manager-panel
sudo systemctl stop gre-manager-panel gre-manager-panel-broker
sudo systemctl start gre-manager-panel
```

`address` prints the configured URL and username, never a password. For old wildcard configs without a saved public IP, it reports the listener and asks you to use a reachable IP. Restart after password reset to revoke existing sessions. Back up the restricted config before manual edits to `listen`, `protocol` (`https`/`http`) or `public_host`, then restart. Switching an HTTP-only installation to HTTPS additionally requires certificate/key files and their absolute paths. Existing TLS files are retained when selecting HTTP.

Setup refuses an existing config or TLS files rather than overwriting them. If an interrupted first setup leaves only TLS files, inspect and move those manager-owned files to a private backup before retrying. A new config contains fields an older published binary may reject; downgrade requires the matching prior configuration and binary. Updating files/services is not a host-wide atomic transaction: an unexpected disk/systemd/startup failure after replacement requires inspecting `journalctl`, retaining the config and restoring the previous matched package if necessary. The installer does not flush firewall rules or remove tunnels.

## Supported adapters

| Area | Supported operations |
| --- | --- |
| Forward/relay management | Multi-port creation, individual edits, bulk selection, enable/disable/delete and review before application |
| iptables/nftables | IPv4/IPv6, TCP/UDP/both, DNAT, destination-port mapping, masquerade/preserve source, interface selection and weighted distribution |
| HAProxy | TCP, weighted targets, round robin/leastconn/source/failover, 20 bounded timeout/queue/maxconn/check/slow-start/PROXY/log options and balanced/VPN/lean presets |
| Realm | TCP/UDP/both, weighted targets, round robin/iphash, timeouts, keepalive/probes, incoming/outgoing PROXY metadata and log level |
| GRE | GRE/ip6gre creation with ID, role, local/peer IP and MTU; service state/actions/logs and dependency-aware deletion |
| FRP | Entrance/destination, TCP/UDP services, TCP/WS/WSS/QUIC transports, stream multiplexing and TCP balancing groups |
| rathole | Entrance/destination, TCP/UDP/both, Noise NK, entrance key creation and public-key pinning at destination |
| Engine installation | Install optional engines selectively or together without creating tunnels |

Current source additionally supports bounded [HAProxy TLS/SNI/HTTP routing](HAPROXY-ROUTING.md), source-IP memory affinity, pinned [Realm WS/MPTCP/IPv6-only profiles](REALM-PROFILES.md), and nftables incremental/source hashing. This remains a closed adapter set: arbitrary native config/ACL editing, Realm native TLS/WSS and hostname destinations are not exposed. Capabilities advertised by the API/forms define the supported profile. Optional [paired GRE/FRP orchestration](PAIRED-CONNECTIONS.md) is separate from the general local editors.

Presets initialize settings; they do not guarantee throughput or resource usage on every route. PROXY metadata requires a compatible receiver. Preserved source IP requires correct return routing. A kernel forward marked configured does not prove peer reachability; an active relay process does not prove end-to-end tunnel health.

Configure GRE/reverse peers independently, or use the explicitly enabled paired GRE/FRP workflow to coordinate two eligible Nodes. The GRE web form does not add watchdogs or global firewall/sysctl changes. Protocol 47 must be allowed by the network. GRE IDs/roles preserve the existing keyed wire contract. GRE/reverse configuration is outside forwarding restore points.

## Interface corrections in Phase 1

The interface remains on Radix/shadcn; Base UI examples are references, not a second installed primitive system. Switches/checkboxes use Radix `data-state` styling, with visible checked states, partial selection, keyboard controls and labels. Dedicated HAProxy/Realm creation pages retain their engine. Optional forward/relay names are available in the normal form; empty names use the existing automatic default. Names still follow backend ASCII/length validation. Current source also supports fingerprint-bound GRE/reverse display names independent of technical service IDs.

The header exposes light/dark/system controls. The official shadcn sidebar composition handles desktop collapse and mobile navigation. Application typography uses locally served Vazirmatn; all system-generated numbers use Latin digits in both languages, while IPs, ports and code retain readable LTR isolation. Forms use mobile input sizing and reachable action footers. Action tooltips support hover/focus; question-mark help also opens on click/tap.

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

The Traffic page now separates usage/cycles from collection settings with tabs. Optional retained history keeps up to 288 actual samples per resource and 12 completed cycle summaries. History is fetched only for the selected resource; summary polling does not transfer all archives. Per-port customer labels, advisory quotas, confirmed cycle resets, CSV export and scoped removal of deleted-resource accounting are supported. Read [Traffic accounting](TRAFFIC-ACCOUNTING.md) for limits, counter semantics, retention and the absence of automatic cutoffs/remote mutations. Optional Agent snapshots are described in [Remote traffic summaries](REMOTE-TRAFFIC.md).

## Architecture and security

The public HTTP/HTTPS service runs as restricted `grepanel`. Privileged operations go to a local root broker through a group-protected Unix socket. Requests are closed, typed operations; no arbitrary shell, argv or file API is exposed. Both Go and Bash validate inputs. Forward writes use the shared lock, complete-state reload, native preflight, snapshots and recovery. Per-row revisions reject stale updates/deletions.

Sessions live in memory for four hours with HttpOnly/SameSite cookies and the Secure flag on HTTPS. Writes require exact Origin and CSRF validation. Login attempts, request/output sizes, sessions and jobs are bounded. Passwords use bcrypt and production has no default credentials. The loopback-only demo is explicitly simulated and cannot execute system commands. Sessions/jobs reset when the public process restarts; a broker-owned operation can finish independently, so refresh actual state after reconnecting.

| Module | Responsibility |
| --- | --- |
| `panel/internal/model` | Typed contracts, capability matrix, TSV validation/conversion |
| `panel/internal/control` | Local broker, Bash adapter, inventory and accounting |
| `panel/internal/auth` | Login, sessions and CSRF |
| `panel/internal/setup`, `panel/internal/config` | One-time setup, bounded address discovery, access validation and certificate/config persistence |
| `panel/internal/httpapi` | HTTP boundary and bounded asynchronous jobs |
| `panel/web/src/features` | Feature pages/forms, independent of theme choices |
| `panel/web/src/experience` | Appearance contract, selection, themes and direction |
| `src/api.sh`, `src/links.sh`, `src/reverse_api.sh` | Validated noninteractive local operations |

Existing TSV v1/v2 remain supported; advanced Realm options use v3. Advanced HAProxy routing uses v4 with a separate field. Older releases cannot load v3/v4: downgrade requires a suitable older snapshot. The terminal keeps its fixed English interface.

## Appearance fidelity and limits

The imported Nettinx palette is preserved. A later user-approved dark foreground override now applies only to orange primary buttons; their earlier white labels had approximately 2.5:1 and 2.62:1 contrast. Sidebar navigation maps hover/active content to existing readable foreground/muted tokens. Remaining raw-token contrast warnings are recorded limitations, not a passed theme-wide gate. Neutral remains an alternative. The later explicit Vazirmatn font choice changes application typography without altering original palette source values.

Fonts are served locally, Persian letter-spacing is zero and technical values retain LTR isolation. Node, Vite and TypeScript are build-time tools; the browser executes the built React JavaScript. Two Go processes run in production, plus whichever tunnel engines are enabled. `GOMEMLIMIT=64MiB` per Go process is a soft runtime memory setting, not a hard RSS cap or measurement of actual use.

## Optional servers and Agents

The **Nodes** page always includes the panel host. To see other servers, explicitly enable the separate TLS Controller listener and install outbound Agents (read-only by default; optional leased GRE/FRP pairing is described in [Paired connections](PAIRED-CONNECTIONS.md)) with hidden, expiring enrollment codes. The panel may run on an entrance, destination or third server; local-only operation needs no Agent. Existing tunnel pages still control only the panel host. See [NODES.md](NODES.md) for setup, protocol/PKI, status interpretation and recovery. This is an unreleased source feature; the existing v1.3.0 archive does not implement it.


## Current advanced profiles and display preferences

See [HAProxy routing](HAPROXY-ROUTING.md) for exact-host SNI/HTTP routes and HTTPS termination with operator-provisioned PEMs, and [Realm profiles](REALM-PROFILES.md) for pinned WS, MPTCP and IPv6-only options. nftables additionally supports incremental and fixed-seed source-IP hash distribution for new flows; iptables retains its existing weighted random profile. All changes remain scoped to manager-owned resources.

GRE/reverse cards have a display-name action. Names use 1–40 ASCII characters; an empty edit restores the technical name. Display metadata is separate from unit IDs, peer tokens and addresses, is fingerprint-bound, and is updated under the existing manager lock with revision checks. It does not rename the network resource. Deleting a managed resource retires its matching display entry.

All system-generated numbers, dates and chart values use Latin digits in Persian and English; language still controls labels and RTL/LTR. Nettinx's original fills remain unchanged. The user approved a dark dark label/icon override on orange primary buttons only, recorded in `approved-overrides.css` and `fidelity.accept`. Other pre-existing contrast limits remain; this is not a claim that the entire palette passes WCAG. The old generic primary-foreground and sidebar pairs still fail the theme-wide contrast audit and are documented, not silently recolored.


## Minimal responsive workflows

Multi-destination connections expose a compact destination preview on hover/focus and a persistent, scrollable list on click/tap. The list includes every endpoint and its relative weight. Weight describes selection share, not a speed/volume cap. Technical endpoints use isolated LTR rendering, and entrance ports do not include a leading colon. Below the desktop breakpoint, connections use touch-friendly cards instead of a horizontally scrolling table; filtered lists paginate 20 records at a time.

Page descriptions and long form explanations move to focus/hover/tap help. Routing and optional IP-affinity controls stay under Advanced settings. The paired GRE/FRP wizard shows entrance and destination as separate server cards, a directional connector and a swap action; on small screens it stacks them vertically. This changes presentation only: existing eligibility, preflight, leasing and rollback contracts still apply.

Mobile navigation provides Overview, Connections, Traffic and Nodes shortcuts plus the full menu. Sidebar hover/active items use existing readable foreground/muted tokens with a stable active indicator. Tooltips use the existing popover surface with a short delay and suppress duplicate hover content while persistent help is open. Brief CSS entry/color transitions respect `prefers-reduced-motion`; no new animation or graph runtime dependency is introduced.
