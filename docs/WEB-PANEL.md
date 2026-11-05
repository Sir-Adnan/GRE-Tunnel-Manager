# Web panel

Manage local tunnels from a Persian/English interface on desktop or mobile. The panel runs separately from the traffic path; stopping it does not stop independently managed tunnels. Other servers can join as optional [Nodes and Agents](NODES.md).

Version **v1.5.0** adds kernel port ranges of up to 4096 ports with mapped remote ports, domain destinations, the server's own DNS (Optimization → DNS), a three-step connection editor with a route map, health and safe-apply choices in the forms, drag-and-drop ordering and an import from Port Forward Manager; see [Port ranges, domain destinations and server DNS](PORTS-AND-DNS.md). Version v1.4.1 added a notification center with webhook and Telegram delivery, a change history with in-place restore, scheduled backups, a guided diagnosis, GRE quality and speed tests, far-side checks through Nodes, an opt-in Prometheus endpoint and a redesigned Optimization page with Apply all, profiles, a network-card group and automatic undo; see [Monitoring](MONITORING.md). Version v1.4.0 added opt-in health failover for kernel forwards, HAProxy check results, a GRE path MTU test and a reversible [Optimization](OPTIMIZATION.md) page. Version v1.3.7 added optional [health monitoring and scheduled maintenance](HEALTH-AND-MAINTENANCE.md) and a 1–15 second dashboard refresh. Version v1.3.6 routes kernel-forward replies for additional IPs that have their own gateway and allows IPv4/IPv6 forwards on one port. Version v1.3.5 redesigned the panel: Signal, Graphite and Aurora presets, one filtered Connections page, a status-first overview with a **Needs attention** list and a Ctrl/Cmd+K command palette. It also fixed iptables/nftables forwarding on servers with additional IPs. Live server readings, optional traffic-quota pauses, reviewed configuration imports, engine maintenance and encrypted portable recovery remain available. See [Traffic accounting](TRAFFIC-ACCOUNTING.md), [Configuration editor](CONFIGURATION-EDITOR.md) and [Backup and restore](BACKUP-RESTORE.md).

## Installation and login

On Debian/Ubuntu with systemd:

```bash
curl -fsSL --ipv4 https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh -o panel-install.sh && sudo bash panel-install.sh --quick
```

The terminal **Web Panel** menu uses the same installer. It downloads a versioned archive, verifies its checksum and installs the Go executable, embedded frontend and matching Bash helper. Managed servers need no Node.js, Python, compiler, Docker or database server.

### Quick and custom setup

Quick setup uses HTTPS, detects the public IP, selects a free random port and generates administrator credentials. The URL and generated password are printed once; save them. Running the installer without `--quick` offers numbered quick/custom and HTTPS/HTTP choices. Custom setup asks for the address, port, username and a hidden, confirmed password.

| Option | Fresh-install behavior |
| --- | --- |
| `--quick` | Automatic setup without questions |
| `--protocol https` / `--protocol http` | Browser protocol; HTTPS by default |
| `--address IP_OR_DOMAIN` | Reachable IP or ASCII domain without scheme, port or path; skips IP discovery |
| `--port PORT` | Selected TCP port; omitted or `0` selects an available random port |
| `--username USER` | Default `admin`; 3–40 ASCII letters, digits, dots, dashes or underscores |
| `--listen LOCAL_IP` | Local bind; all IPv4 addresses by default, or `::` for an IPv6 address |
| `--install-engines` | Preinstall supported engines without creating tunnels; none by default |
| `--package-dir DIR` | Use a matching local archive and `SHA256SUMS` |

After downloading the installer, for example:

```bash
sudo bash panel-install.sh --quick --protocol http --address 203.0.113.10 --port 8080
sudo bash panel-install.sh --quick --address panel.example.com --port 8443
```

Chosen passwords require at least eight Unicode characters and at most 72 UTF-8 bytes. Quick setup generates a 32-character random password. Password arguments, URLs and environment variables are not accepted; only the bcrypt hash is stored. Avoid saving the one-time credential output in shared logs.

### Address discovery, certificates and access

Allow the selected TCP port in the server/provider firewall. Setup checks current sockets but does not model all custom DNAT rules or automatically open firewalls. A random port is not an authentication mechanism.

When no address is supplied, bounded HTTPS requests to `api.ipify.org` and `api6.ipify.org` discover the outgoing public IP. Behind NAT or on multi-address servers, pass the actual reachable entrance with `--address`. Failed quick discovery stops before configuration is written. A domain must already resolve to the server; setup does not register it or edit DNS. IPv6 URLs use brackets; domain listeners default to IPv4 unless `--listen ::` is supplied.

HTTPS initially uses a self-signed certificate. Verify its SHA-256 fingerprint over SSH before trusting it. For an operator-managed certificate, set absolute `certificate` and `private_key` paths in the restricted configuration and restart. Automatic ACME and trusted reverse-proxy/forwarded-header support are not implemented; access and Origin checks refer to the direct listener.

Explicit HTTP works on an IP without a certificate, but browser login and management traffic are unencrypted. Authentication, Origin and CSRF checks remain required. Browser HTTP does not weaken the separate TLS Agent channel.

### Existing installations and recovery

Run the current installer again to upgrade to the matching **v1.5.0** package, then refresh the browser. Downloading the script alone does not replace an installed binary. The installer preserves existing address, protocol, credentials and certificates; setup flags do not reconfigure an existing installation.

Checksums, binary version and existing configuration are checked before a working service stops. Installation is locked against concurrent runs. If an upgraded panel fails to start, the installer reinstalls the previous executable and helper and starts them again. Rewritten unit files stay in place. That rollback is not a host-wide atomic transaction: inspect logs when it reports failure. Keep private backups of configuration and Node identities.

The broker is enabled at boot independently of the public panel. Traffic sampling and opt-in quota pauses keep running while the panel is stopped, restarting or failing.

```bash
sudo gtm-panel address
sudo gtm-panel reset-password
sudo systemctl restart gre-manager-panel
sudo systemctl status gre-manager-panel --no-pager
sudo journalctl -u gre-manager-panel -n 100 --no-pager
```

The address command never prints a password. Restart after password reset to revoke existing sessions. Back up the config before changing its listen/protocol/public_host fields; switching from HTTP to HTTPS also requires certificate/key files. Existing TLS files are retained when selecting HTTP.

An interrupted first setup can leave TLS files; inspect and move only those owned files to a private backup before retrying. Older binaries may reject newer configuration/state schemas, so downgrade needs matching prior backups. See [Operations](OPERATIONS.md) and [panel removal](PANEL-REMOVAL.md).

## Connections and configuration

| Area | Managed features |
| --- | --- |
| iptables/nftables | IPv4/IPv6 TCP/UDP forwarding, port ranges of up to 4096 ports in one rule, mapped ports (nftables), domain destinations, source policy, weighted destinations and owned rules |
| HAProxy | TCP, checks, balancing/failover, bounded IP affinity and TLS/SNI/HTTP routing |
| Realm | TCP/UDP, weighted targets, timeouts/keepalive, PROXY metadata and gated transport options |
| GRE | Keyed GRE/ip6gre setup, MTU, names, service actions and dependency-aware removal |
| FRP/rathole | Entrance/destination setup, supported transports and service actions |

The [capability matrix](ENGINE-CAPABILITIES.md) defines supported versions and limits. Adapters do not expose every native engine option. General editors act on the panel host; remote writes are limited to [coordinated GRE/FRP creation](PAIRED-CONNECTIONS.md).

The connection editor has three steps — **Entrance** (engine, ports or ranges, protocol, how ports map to the remote side), **Destinations** (addresses or domains checked when you leave the field, weights, drag to set the failover order, domain refresh, balancing and the advanced engine options) and **Protection & review** (health monitoring, automatic failover, notifications, safe apply and the review) — beside a live **route map** on desktop; on phones the map folds into the summary bar. Names are optional. Review precedes every apply. See [Port ranges, domain destinations and server DNS](PORTS-AND-DNS.md). Changed connection, GRE/reverse and configuration drafts ask before closing; drafts are not stored in the browser. **Relative share** controls weighted distribution, not priority or a bandwidth guarantee. [Setup presets](CONNECTION-PROFILES.md) initialize settings without changing existing records automatically.

HAProxy, Realm and kernel port forwards share one **Connections** page; chips filter it by engine and show counts. Each row has an on/off switch, **Edit** and a health dot; selecting rows shows a floating bar for bulk start, stop and delete. Drag a row by its handle (or focus the handle and press the arrow keys) to reorder; the order is saved on the server for every device and never changes configuration. **Duplicate** in the row menu opens the same settings on the next free port or range. Select a connection name to inspect its summary and copy destination endpoints. The **More actions** menu contains details, configuration, supported logs and deletion. The toolbar's **Preview all configurations** renders enabled local connections without applying anything. The [configuration editor](CONFIGURATION-EDITOR.md) supports managed JSON and a restricted native-text subset, with revision checks, validation and review. GRE/reverse file views are read-only; reverse secrets are masked. Arbitrary paths, commands and unrestricted overrides are not exposed.

Page addresses such as `#/connections?engine=haproxy` can be bookmarked; links to the earlier `#/haproxy`, `#/realm` and `#/forwarding` pages open the matching filter. Press **Ctrl K** (**Cmd K** on macOS), or use the sidebar search, to jump to pages, filters, saved connections, creation forms and appearance settings. Search/status filters, selected connection details and traffic tabs are retained in the URL. Browser back/forward works between pages. The header's server button shows the local host, protocol and separately copyable IPv4/IPv6 addresses. These remain local operations; remote management is limited to the capabilities described below.

## Traffic usage

Collection and retained history are off by default. Tabs separate **All connections**, **Details & history** and **Traffic collection**. The list has search, method filters, 20-row pages and per-row actions for labels/quotas, reset, supported manual stop or forgetting deleted-resource accounting. Missing samples display as unavailable.

Collection adds only owned `inet gtm_panel_metrics` counters and periodic sampling, including for iptables/relay ports. GRE uses interface counters. Disabling removes the accounting table and pauses sampling while retaining totals; existing automatic-pause policies must be turned off first. Disable collection before stopping the panel if you want those kernel counters removed.

Bytes are network-layer usage, not provider billing. GRE and forwarding counters may overlap and are never summed. Quotas are advisory by default; an explicit automatic-pause option installs scoped kernel drop rules at the next successful sample after a crossing. This is not an exact byte limiter. History is bounded; remote summaries are read-only. See [Traffic accounting](TRAFFIC-ACCOUNTING.md) for coverage, lost-sample limits, reset semantics and CSV export.

## Health and maintenance

Both pages are off by default and cost nothing while off. **Health** checks every enabled destination (TCP connect, or ping for UDP-only services), GRE peers and managed service units on a schedule, and keeps status, 24 h / 7 d / 30 d uptime, outages, a weekly report (CSV and print) and conntrack/CPU pressure from `/proc`. **Maintenance** runs plans: a soft refresh without disconnects, a restart (for kernel forwards, clearing only that forward's tracked flows) or a server reboot, on daily, weekday, interval, uptime or health triggers, with guards such as a time window, quiet traffic, cooldown, daily limit, cancellable notice, minimum uptime and dry run. Health can also fail over kernel forwards with several destinations, shows HAProxy's own check results, connection counts per destination and an on-demand GRE path MTU test. See [Health and maintenance](HEALTH-AND-MAINTENANCE.md).

Connection and GRE forms set monitoring, failover and notifications per owner, and offer to turn health checks on when they are off; **Safe apply** reverts a change after 2–10 minutes unless it is confirmed in the banner. See [Health and maintenance](HEALTH-AND-MAINTENANCE.md#choices-in-the-forms).

Each Health row also offers **Diagnose** (a read-only "why isn't it working?" checklist) and, for GRE, a **Quality test** (latency, jitter, loss); tunnels a Node also reports show whether the far side reaches them. See [Monitoring](MONITORING.md).

## Optimization

The **Optimization** page is a control center: progress for the chosen profile, **Apply all** and **Review recommendations**, the profile (a three-stop intensity and goal cards) and the server facts in one card, then five opt-in groups (Connection tracking, Packet queues, Relay TCP, Tunnels & routing, Network card) reviewed with current, recommended and original values. Any value can be customized within safe bounds; worse values need a confirmation. Undo goes back step by step, a group can be restored and everything reset, and an apply can be watched with automatic undo when tunnels go down. See [Server optimization](OPTIMIZATION.md).

The **DNS** tab sets the server's own resolvers from international or Iranian presets or by hand, tests their speed from the server, keeps them across reboots and restores the original. See [Port ranges, domain destinations and server DNS](PORTS-AND-DNS.md#server-dns-optimization--dns).

## Change history

**Change history** lists every forwarding change as a timeline grouped by day: which connections were added, removed or changed and which fields. **Restore to before this** shows exactly what restoring would change now and restores through the normal apply path after a revision check; the current state is saved first, so the restore appears in the history and can be undone. GRE tunnels, reverse tunnels and optimization keep their own undo.

## Notifications and metrics

The bell in the header opens the notification center; **Settings → Notification channels** sends selected events to a webhook or Telegram bot, and **Settings → Metrics export** enables a token-protected Prometheus endpoint. **Backups → Schedule** saves recovery snapshots on a schedule. See [Monitoring](MONITORING.md) and [Backup and restore](BACKUP-RESTORE.md#scheduled-backups).

## Configurations and engines

Configuration actions now open supported text editors directly. Use **Import** to convert a pasted/file HAProxy TCP configuration, simple Realm TOML or managed JSON into reviewed connections; it saves without starting unless explicitly enabled. See [Configuration editor](CONFIGURATION-EDITOR.md). **Tunnel engines → Check versions** separates current, official and verified/distribution versions and offers explicit local updates; see [Engine maintenance](ENGINE-MAINTENANCE.md).

## Multiple servers

The panel host is already a local Node and needs no Agent. Nodes has separate server inventory and **Connect two servers** tabs. **Add server** opens setup guidance when the Controller is disabled. Enable its dedicated TLS listener, allow its port and refresh, then create an invitation for the other server's outbound Agent. Browser HTTP and Agent TLS are independent. See [Nodes](NODES.md), [paired connections](PAIRED-CONNECTIONS.md) and [remote traffic](REMOTE-TRAFFIC.md).

## Security and runtime

The public service runs as restricted `grepanel`; privileged typed operations use a protected local Unix broker and Bash API. Forwarding changes reload complete locked state, compare revisions, validate, snapshot and recover on failure. No public shell or arbitrary-file API exists.

Sessions are memory-only, expire after four hours and use HttpOnly/SameSite cookies plus Secure on HTTPS. Writes require exact Origin and CSRF checks. Requests, login attempts and jobs are bounded. Restarting the public process clears sessions/jobs; a broker operation can still finish, so refresh actual state after reconnecting.

Production runs two Go processes plus the selected tunnel engines. Node/Vite/TypeScript are build tools. A memory-limit setting is not a fixed RSS guarantee; no throughput, CPU or RAM benchmark is claimed. For implementation details, see [Architecture](ARCHITECTURE.md), [Server artifacts](ARTIFACTS.md) and [Interface conventions](INTERFACE.md).

## Live dashboard activity

The dashboard adds CPU utilization across all cores, used/available memory, and receive/send rates. The authenticated read-only `/api/host/telemetry` action reads bounded `/proc/stat`, `/proc/meminfo`, `/proc/net/dev` and default-route files directly; it does not invoke shell commands or scan services. CPU excludes duplicate guest accounting and treats idle/iowait as idle. RAM uses `MemAvailable`, including reclaimable cache.

Network rates use the deduplicated interfaces having IPv4/IPv6 default routes, not a sum of GRE and physical interfaces. Their names are visible. This is host interface traffic, not per-tunnel traffic or a complete policy-routing/link-bond accounting model. Traffic through other policy routes is not included. Rate values require two valid samples. Route/counter changes or gaps longer than 30 seconds restart the baseline rather than displaying a spike or zero.

The visible dashboard requests a sample every 2 seconds by default; choose 1, 2, 5 or 15 seconds (remembered in this browser) or pause it. Below one second the network rate is noise, so it is not offered. Hidden/unmounted dashboards stop requests. Open tabs share a sub-second server cache, so the files are read at most about once per second. No new agent, daemon, database, disk history, Prometheus or packet capture is installed. These samples are independent of optional per-connection accounting. Demo readings are simulated. See [Kernel and userspace](KERNEL-AND-USERSPACE.md) for the execution split.

## Overview, navigation and appearance

The overview starts with the server's status: host name, OS and primary address, then four tiles for connections, running services, items that need attention and uptime/load. **Needs attention** lists enabled services in a failed or stopped state and engines that enabled connections use but that are not installed; each entry opens the related page. It is derived from inventory, not a separate health check.

The sidebar groups **Workspace** (Overview, Connections, Traffic, Health), **Network** (Nodes, GRE, Reverse tunnels) and **System** (Maintenance, Optimization, Tunnel engines, Backup & restore, Settings). Phones keep Overview, Connections, Traffic and Nodes in the bottom bar.

Appearance is stored only in this browser. **Signal** (dark) is the default; **Graphite**, **Aurora**, **Nettinx** and **Neutral** are available from the header's appearance button, the command palette or **Settings**, each in light, dark or system mode. Browsers that had the earlier automatic Nettinx default move to Signal once; a preset chosen afterwards is kept. Interface motion is short and is disabled when the operating system asks for reduced motion.
