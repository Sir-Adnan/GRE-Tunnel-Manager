# Web panel

Manage local tunnels from a Persian/English interface on desktop or mobile. The panel runs separately from the traffic path; stopping it does not stop tunnels. Other servers can join as optional [Nodes and Agents](NODES.md). Release notes are in the [Changelog](CHANGELOG.md).

## Installation and login

On Debian/Ubuntu with systemd:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh | sudo bash
```

The installer downloads the prebuilt release, verifies its SHA-256 checksum and starts a short setup: address, connection security, port, login and optional engines. Every answer has an option for unattended installs, for example:

```bash
curl -fsSL .../install.sh | sudo bash -s -- --yes
curl -fsSL .../install.sh | sudo bash -s -- --domain panel.example.com --email ops@example.com --port 2053 --yes
curl -fsSL .../install.sh | sudo bash -s -- --http --domain 203.0.113.10 --port 8080 --yes
```

`--yes` uses the defaults: trusted HTTPS from Let's Encrypt for the detected public IP, a free random port, user `admin` and a generated password. The summary shows the address and the password once. Managed servers need no Node.js, Python, compiler, Docker or database server. All options, and the `gtm` command that maintains the panel afterwards, are in [Command line](COMMAND-LINE.md).

### Address, certificates and access

Allow the panel's TCP port in the server and provider firewall; the installer does not open firewalls. A random port is not an authentication mechanism.

Without `--domain`, bounded HTTPS requests to `api.ipify.org` and `api6.ipify.org` detect the outgoing public IP. Behind NAT or on multi-address servers, pass the reachable address with `--domain`. A domain must already resolve to the server. IPv6 URLs use brackets; domain listeners use IPv4 unless `--listen ::` is given.

Let's Encrypt validates over TCP port 80 for a few seconds, or over Cloudflare DNS for a domain. If issuance fails, the panel keeps a self-signed certificate and the installation still completes; **Settings → Security → Get trusted certificate** or `sudo gtm https issue` retries. `--self-signed` skips Let's Encrypt: verify the printed SHA-256 fingerprint over SSH before trusting it. See [HTTPS and certificates](HTTPS.md). Trusted reverse-proxy/forwarded-header support is not implemented; access and Origin checks refer to the direct listener.

`--http` serves the panel without encryption: login and management traffic are readable on the network. Authentication, Origin and CSRF checks remain required, and the Agent channel keeps its own TLS.

Passwords need at least eight characters and at most 72 UTF-8 bytes; only the bcrypt hash is stored. Prefer `--password-env NAME` (with `sudo --preserve-env=NAME`) over `--password`, which is visible in shell history.

### Certificates from the browser

**Settings → Security → Panel connection security** shows the loaded certificate and offers:

- **Get trusted certificate** (or **Request new certificate**): a domain that points to this server or a public IP, an optional email and an untrusted staging test. Let's Encrypt validates over TCP port 80, so allow it in the server and provider firewall. An HTTP panel restarts on HTTPS at the new address, where you sign in again; the page counts down and opens it.
- **Renew now** for a certificate the panel renews itself.
- **Switch to self-signed**, for example when a trusted certificate can no longer be renewed. Automatic renewal stops.

These are broker jobs with fixed commands; the browser sends only the address, email and staging choice. Cloudflare DNS validation stays a terminal command (`sudo gtm https issue`) so the API token never passes through the public process. A failed request leaves the loaded certificate in place. See [HTTPS and certificates](HTTPS.md).

### Sign-in security

**Settings → Security → Sign-in** turns on two-factor sign-in with any authenticator app (time-based six-digit codes): scan the QR code or type the key, enter one code to prove the app works, then save the ten single-use recovery codes, which are shown once. Sign-in then asks for a code after the password; a recovery code works in the same field. Turning it off needs the password and a code. With the phone and the codes lost, `sudo gtm 2fa off` turns it off on the server and signs everyone out.

The same card lists the browsers signed in now (browser, system, address, last activity) and signs out one or all others. Sessions stay memory-only: they end after four hours and whenever the panel restarts.

The secret and the hashes of unused recovery codes are stored in `/etc/gre-manager-panel/two-factor.json` (root-owned, readable by the panel group, like the password hash). Only the broker writes it; codes cannot be replayed within their 30-second window. Damaged settings stop the panel from starting rather than accepting the password alone.

### Updates and recovery

**Settings → Updates** shows the installed release, the newest one from the daily check and its release notes; the sidebar names a newer release under the version. **Check now** asks the release server again. **Update to vX** asks for confirmation, then the broker starts `gtm update` for exactly that version in its own transient unit (`gre-manager-panel-update.service`), so the restart it causes cannot interrupt it. The page waits, then reloads into the new release; sign in again. If the update fails, the previous release keeps running and the page shows the reason; `sudo gtm logs update` has the details.

`sudo gtm update` does the same from SSH. The current release is copied aside first; if the new one does not start, it is restored and started again. The daily timer only checks for new releases (`gtm status` shows the result) and never installs anything; `--no-update-check` turns the timer off. Running `install.sh` again repairs an installation and keeps its address, protocol, login and certificates.

Checksums, the package version and the existing configuration are checked before any service stops, and installation is locked against concurrent runs. Rollback covers the executable and engine script, not the whole host: read the logs when it reports a failure. The broker starts at boot independently of the public panel, so traffic sampling and opt-in quota pauses continue while the panel is stopped or restarting.

```bash
sudo gtm                 # status and menu
sudo gtm password        # new login password; signs out every session
sudo gtm port 2053       # move the panel; a failed start restores the old port
sudo gtm logs -f         # follow the panel log
```

Older binaries may reject newer configuration or state schemas, so a downgrade needs matching backups. See [Operations](OPERATIONS.md) and [Panel removal](PANEL-REMOVAL.md).

## Connections and configuration

| Area | Managed features |
| --- | --- |
| iptables/nftables | IPv4/IPv6 TCP/UDP forwarding, port ranges of up to 4096 ports in one rule, mapped ports (nftables), domain destinations, source policy, weighted destinations and owned rules |
| HAProxy | TCP, checks, balancing/failover, bounded IP affinity and TLS/SNI/HTTP routing |
| Realm | TCP/UDP, weighted targets, timeouts/keepalive, PROXY metadata and gated transport options |
| GRE | Keyed GRE/ip6gre setup, MTU, names, service actions and dependency-aware removal |
| FRP/rathole | Entrance/destination setup, supported transports and service actions |

The [capability matrix](ENGINE-CAPABILITIES.md) defines supported versions and limits. Adapters do not expose every native engine option. General editors act on the panel host; remote writes are limited to [coordinated GRE/FRP creation](PAIRED-CONNECTIONS.md).

The connection editor has three steps — **Entrance** (engine, ports or ranges, protocol, how ports map to the remote side), **Destinations** (addresses or domains checked when you leave the field, weights, drag to set the failover order, domain refresh, balancing and the advanced engine options) and **Protection & review** (health monitoring, automatic failover, notifications, safe apply and the review) — beside a live **route map** on desktop; on phones the map folds into the summary bar. Each step is a few titled cards, the method is picked from cards with a one-line explanation, and **Next** names the step it opens. A field that needs a fix shows why under it; with several, a summary at the top links to each. Names are optional. Review precedes every apply. See [Port ranges, domain destinations and server DNS](PORTS-AND-DNS.md). A new connection can **start from a template**:
- *VPN to a foreign server*: TCP and UDP on one port, forwarded in the kernel.
- *HTTPS / TLS relay*: HAProxy.
- *A range of ports*.
- *Several foreign servers*: balanced, with checks.
- *Through a GRE tunnel*: offered when a GRE tunnel exists; it targets the tunnel's far-end inner address.

Templates are one row of chips above the form (a sideways row on phones); the chosen one is explained under the row. A template fills the engine, protocol, ports and destination shape. Addresses already typed are kept, and everything stays editable. The templates are also in the command palette.

Changed connection, GRE/reverse and configuration drafts ask before closing; drafts are not stored in the browser. **Relative share** controls weighted distribution, not priority or a bandwidth guarantee. [Setup presets](CONNECTION-PROFILES.md) initialize settings without changing existing records automatically.

HAProxy, Realm and kernel port forwards share one **Connections** page; chips filter it by engine and show counts. Each row starts with a status icon and shows its route on one line: entrance protocol and ports, a wire and the destinations (several destinations open a list). The icon and the wire share one state, derived from the service state, health checks and firewall badges:
- **Running** (green, the wire drifts toward the destination): nothing known blocks the connection. It is not a traffic measurement; the Check tab measures traffic.
- **Needs a look**: degraded health checks or a relay port closed in UFW.
- **Stopped or blocked**: a stopped or failed service, failing checks, or a firewall that drops the forward.
- **Turned off**, or **Changing or not known yet**.

Each row also has an on/off switch, **Edit** and a health dot; selecting rows shows a floating bar for bulk start, stop and delete. **Sort** orders the list by name, status or engine, or keeps your custom order. **Reorder** turns the list into compact, numbered rows: drag a row by its handle (on a touch screen, press and hold anywhere on it), focus the handle and press the arrow keys, or use the row's ⋯ menu to move it to the top, up, down or to the bottom. **Save order** in the floating bar keeps it and **Cancel** puts it back; the saved message offers **Undo**. The custom order is saved on the server for every device and never changes configuration. On phones, **Select** or a long press on a card starts selection mode for bulk actions. **Duplicate** in the row menu opens the same settings on the next free port or range.

Badges under each name show:
- **Server IP** or **Client IP**: the address the destination sees (masquerade, or a preserved source).
- **Forward blocked**: a dropping iptables backend lacks the owned accept.
- **Closed in UFW**.
- An allow or block list with its size.
- **Limited**: per-source limits apply.

The firewall badges open that connection on the [Firewall](FIREWALL.md) page.

Select a connection name to inspect its summary, its **Check** tab and destination endpoints. Saving an enabled connection opens its Check tab at once.

The **Check** tab shows the **live packet path** (clients → firewall → this server → each destination) with the guided checks below it:
- Kernel forwards read the manager's own rule counters every 3 s while the tab is open: new connections per second, packets and bits per second to and from each destination, and packets the firewall's access rules dropped.
- Relays show the TCP clients and the connections open to each destination.
- A verdict names where traffic stops: waiting for traffic, dropped by this server's firewall (with **Fix now**), arriving but not leaving, a destination that does not answer, or only some destinations answering.
- The first sample shows totals since the rules were applied; rates follow with the next one.
- Nothing is sent to test it.

A failed operation explains itself. Known causes get a plain sentence, **what to do** and, where a page fixes it, a button that opens that page. Examples: a port in use, settings changed meanwhile, server DNS, the firewall, a missing engine, a name that does not resolve, an IP no longer on the server, and a configuration that fails its check. The engine's own message stays under *Technical details*.

The **More actions** menu contains details, configuration, supported logs and deletion. The toolbar's **Preview all configurations** renders enabled local connections without applying anything. The [configuration editor](CONFIGURATION-EDITOR.md) supports managed JSON and a restricted native-text subset, with revision checks, validation and review. GRE/reverse file views are read-only; reverse secrets are masked. Arbitrary paths, commands and unrestricted overrides are not exposed.

Page addresses such as `#/connections?engine=haproxy` can be bookmarked; links to the earlier `#/haproxy`, `#/realm` and `#/forwarding` pages open the matching filter. Press **Ctrl K** (**Cmd K** on macOS), or use the sidebar search, to jump to pages, filters, saved connections, creation forms and appearance settings. Choosing a saved connection lists what to do with it: details, check, edit, turn on or off, duplicate, configuration or delete (which still asks for confirmation); Backspace or Escape goes back.

On phones, dialogs open from the bottom of the screen and close by dragging their handle down. A connection card can be swiped: one way shows **Turn off/on** and **Edit**, the other way **More** with the remaining actions. Delete is never done by a swipe. The bottom bar's **More** opens every other page plus *New connection* and *Search and commands*; a dot marks pages that need attention, and the bar steps aside while you scroll down a page. Search/status filters, selected connection details and traffic tabs are retained in the URL. Browser back/forward works between pages. The header's server button shows the local host, protocol and separately copyable IPv4/IPv6 addresses. These remain local operations; remote management is limited to the capabilities described below.

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

## IP addresses

**IP addresses** lists this server's addresses and what uses each. After the datacenter changes an IP, **IP changed** moves every GRE end, connection and reverse tunnel to the new address on one screen; the other end of a tunnel moves automatically when it is a v1.6.0+ Node, and other peers get a command. **Add IP** keeps an additional address, with an optional own gateway, in an owned unit. See [IP addresses](IP-ADDRESSES.md).

## Multiple servers

The panel host is already a local Node and needs no Agent. Nodes has separate server inventory and **Connect two servers** tabs. **Add server** opens setup guidance when the Controller is disabled. Enable its dedicated TLS listener, allow its port and refresh, then create an invitation for the other server's outbound Agent. Browser HTTP and Agent TLS are independent. See [Nodes](NODES.md), [paired connections](PAIRED-CONNECTIONS.md) and [remote traffic](REMOTE-TRAFFIC.md).

## Security and runtime

The public service runs as restricted `grepanel`; privileged typed operations use a protected local Unix broker and Bash API. Forwarding changes reload complete locked state, compare revisions, validate, snapshot and recover on failure. No public shell or arbitrary-file API exists.

Sessions are memory-only, expire after four hours and use HttpOnly/SameSite cookies plus Secure on HTTPS. Optional two-factor sign-in is described under [Sign-in security](#sign-in-security). Writes require exact Origin and CSRF checks. Requests, login attempts and jobs are bounded. Restarting the public process clears sessions/jobs; a broker operation can still finish, so refresh actual state after reconnecting.

Production runs two Go processes plus the selected tunnel engines. Node/Vite/TypeScript are build tools. A memory-limit setting is not a fixed RSS guarantee; no throughput, CPU or RAM benchmark is claimed. For implementation details, see [Architecture](ARCHITECTURE.md), [Server artifacts](ARTIFACTS.md) and [Interface conventions](INTERFACE.md).

## Live dashboard activity

The dashboard adds CPU utilization across all cores, used/available memory, and receive/send rates. The authenticated read-only `/api/host/telemetry` action reads bounded `/proc/stat`, `/proc/meminfo`, `/proc/net/dev` and default-route files directly; it does not invoke shell commands or scan services. CPU excludes duplicate guest accounting and treats idle/iowait as idle. RAM uses `MemAvailable`, including reclaimable cache.

Network rates use the deduplicated interfaces having IPv4/IPv6 default routes, not a sum of GRE and physical interfaces. Their names are visible. This is host interface traffic, not per-tunnel traffic or a complete policy-routing/link-bond accounting model. Traffic through other policy routes is not included. Rate values require two valid samples. Route/counter changes or gaps longer than 30 seconds restart the baseline rather than displaying a spike or zero.

The visible dashboard requests a sample every 2 seconds by default; choose 1, 2, 5 or 15 seconds (remembered in this browser) or pause it. Below one second the network rate is noise, so it is not offered. Hidden/unmounted dashboards stop requests. Open tabs share a sub-second server cache, so the files are read at most about once per second. No new agent, daemon, database, disk history, Prometheus or packet capture is installed. These samples are independent of optional per-connection accounting. Demo readings are simulated. See [Kernel and userspace](KERNEL-AND-USERSPACE.md) for the execution split.

## Overview, navigation and appearance

Until every step is done, a **Get started** checklist sits under the header: trusted HTTPS, two-factor sign-in, a first connection, health monitoring, scheduled backups and Telegram or webhook alerts. Each step reads the server's real state and links to its page; the card can be hidden in this browser.

The overview starts with the server's status: host name, OS and primary address, then four tiles for connections, running services, items that need attention and uptime/load. **Needs attention** lists, first, local addresses that saved settings still use but the server no longer has (after an IP change), then enabled services in a failed or stopped state and engines that enabled connections use but that are not installed; each entry opens the related page. It is derived from inventory, not a separate health check.

The sidebar groups **Workspace** (Overview, Connections, Traffic, Health), **Network** (Nodes, GRE, Reverse tunnels, Firewall, IP addresses) and **System** (Maintenance, Optimization, Tunnel engines, Backup & restore, Settings). Phones keep Overview, Connections, Traffic and Nodes in the bottom bar.

Appearance is stored only in this browser. **Signal** (dark) is the default; **Graphite**, **Aurora**, **Nettinx** and **Neutral** are available from the header's appearance button, the command palette or **Settings**, each in light, dark or system mode. Browsers that had the earlier automatic Nettinx default move to Signal once; a preset chosen afterwards is kept. **Density** (Comfortable or Compact, in the same places) changes the spacing of rows, cards and page sections; text sizes stay the same. Interface motion is short and is disabled when the operating system asks for reduced motion.

The live server readings on the overview draw a trend line of about the last minute of samples. It is kept in the page's memory only and starts again when the page is opened.
