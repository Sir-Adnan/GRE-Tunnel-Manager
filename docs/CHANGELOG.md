# Changelog

## v1.6.0 — Panel-only management, installer and `gtm`, trusted HTTPS, two-server wizard

- **Tunnel to a foreign server** wizard (Connections → **Two servers**, the command palette, or the first step of the Overview checklist). Three steps on the entrance server: the foreign server's IP (this server's address, the lowest free tunnel ID and MTU 1430 are filled in), the public ports and protocol, then a review with the route and the values to enter on the foreign server, each copyable. Create runs `gre-create` (this server as Side B) and then a kernel forward to the far inner address `10.0.ID.1` with the same port numbers. If the forward fails, the tunnel is kept and **Try again** retries only the forward; the failure is explained in place. Checks before anything runs: address and family, a used tunnel ID, MTU bounds, malformed ports and ports another connection already uses for the same protocol, and the engine's name rule. See [User guide](USER-GUIDE.md#tunnel-to-a-foreign-server).
- **Latency history** for each monitored connection under Health: average round trip with its peak band and failed checks, for the last hour, 24 hours, 7 days or 30 days, with the range's average, peak, jitter and loss. It reads the data the monitor already keeps (recent checks and hourly rollups); nothing extra is probed or stored. New read action `health-latency` (`GET /api/health/latency?owner=…&range=1h|24h|7d|30d`). See [Health and maintenance](HEALTH-AND-MAINTENANCE.md#latency-history).
- **Node offline notifications.** The Controller notices when an online Node has not reported for three minutes, and when it reports again, and the notification center records both (`node-offline`, `node-online`) with the silence or outage length; Telegram and webhook deliver them when selected. Fresh installations select both; existing installations keep their saved choice and can turn them on under Notifications. The watcher reads in-memory reports every 30 seconds, adds no network traffic, and stays quiet for a Node that was already down when the panel started. The unprivileged panel reports through a new light broker action, `notifications-node`, that validates the Node ID, name and duration; no browser route reaches it and the read-only Agent broker refuses it. See [Monitoring](MONITORING.md#node-offline-notifications).
- **Server messages in the interface language.** The panel's own answers (sign-in, two-factor, sessions, certificates, updates, busy or expired requests) are shown in Persian or English through one catalogue (`lib/server-messages.ts`); engine reports stay as they are with their explanation. A test fails when a catalogued sentence no longer exists in the Go sources. About 60 places that showed raw errors use the same translator.
- **Typography and touch.** The document root now carries the interface language and direction, so English pages use the Latin line height and heading spacing (Persian rules applied to both before), screen readers announce the right language and dialogs follow the direction. Addresses, ports, table cells and other live figures use tabular digits. On phones, segmented controls and small buttons get larger touch targets. The sidebar's update notice fits on one line in Persian.
- **Panel administration in the browser.** See [Web panel](WEB-PANEL.md#certificates-from-the-browser).
  - **Certificates:** Settings → Security requests a Let's Encrypt certificate over port 80 for a domain or public IP (optional email and staging test), renews a managed one now, or switches to self-signed. An HTTP panel restarts on HTTPS and the page opens the new address. The broker runs fixed `gtm-panel certificate` commands with validated arguments; Cloudflare DNS stays in the terminal so its token never passes through the public process.
  - **Updates:** a new Settings → Updates tab shows the installed and latest release (from the daily check) with release notes and **Check now**; the sidebar names a newer release. **Update to vX** starts `gtm update` for exactly that version in a transient `gre-manager-panel-update.service`, so the restart it causes cannot cut it off; the page waits and reloads into the new release, or shows why it failed while the previous release keeps running. The result is kept in the root-only `update-run.json`, and `gtm logs update` includes the unit.
  - **Two-factor sign-in (TOTP)** with any authenticator app: QR code or key, one verified code before it turns on, ten single-use recovery codes shown once, codes not reusable within their window. Turning it off needs the password and a code; `sudo gtm 2fa off` is the recovery path. Settings live in `/etc/gre-manager-panel/two-factor.json`, outside `config.json`, so a rollback to an older release still loads its configuration; damaged settings keep the panel down rather than accept the password alone. `gtm status` shows it.
  - **Signed-in browsers:** browser, system, address and last activity per session, with sign-out of one or all others.
  - **Get started** checklist on the Overview until each step is done: trusted HTTPS, two-factor sign-in, a first connection, health monitoring, scheduled backups, alerts. It reads the server's real state and can be hidden.
  - New dependency: `rsc.io/qr` (BSD) for the QR code; the page draws its modules, no image or markup crosses the API.

- **New installer and the `gtm` command.** `curl -fsSL …/install.sh | sudo bash` downloads the release, verifies its SHA-256 checksum and starts a short setup: address, connection security, port, login and engines, with arrow keys and live validation; Esc cancels before anything changes. Every answer is also an option (`--domain`, `--port`, `--user`, `--password-env`, `--password`, `--https`/`--self-signed`/`--http`, `--email`, `--cloudflare-token-file`, `--engines`, `--yes` …), so a one-liner installs without questions. The default is trusted Let's Encrypt HTTPS for the detected public IP with a self-signed fallback, a random port and a generated password shown once. See [Command line](COMMAND-LINE.md).
  - `sudo gtm` shows services, address, certificate, Nodes and updates above a menu. Commands: `status [--json]`, `update [--check]`, `https` (issue, renew, self-signed, install), `port`, `password`, `logs`, `agent install|remove`, `controller enable`, `remove`.
  - `gtm update` downloads and verifies the newer release, then runs its own installer. The current release is copied aside first and restored when the new one does not start. A daily timer (`gre-manager-panel-update-check`) only records whether a newer release exists; nothing installs itself. `--no-update-check` turns it off.
  - `gtm port` and `gtm password` change the listener or login, restart only the public panel and restore the previous settings if it does not come back.
  - Agents install with `install.sh --agent` and can now be removed (`gtm agent remove`, refused while a paired operation is pending).
  - Passwords and Cloudflare tokens come from hidden prompts, environment variables or root-only files; `gtm` never puts them in a command line it runs.
  - Installation, update, removal and the Agent moved from Bash to tested Go packages (`internal/install`, `internal/gtm`, `internal/tui`, `internal/release`). `panel-install.sh` and `node-install.sh` remain as shims that translate the earlier options (`--quick` keeps its self-signed default). `gre.sh` without arguments opens `gtm`. A recognized old `igre` copy becomes a script that opens `gtm`.
  - New dependencies (terminal interface only): Charm's Huh, Bubble Tea, Bubbles and Lip Gloss with their MIT/BSD dependencies; licenses ship in `LICENSES/GoDependencies.txt`, generated by `tools/go_licenses.py`.
- **Trusted HTTPS built in.** `sudo gtm https issue` (or `gtm-panel certificate issue`) gets a Let's Encrypt certificate for the panel's domain or public IP and renews it automatically; new installations request one by default. A failed order never fails the installation or replaces the loaded certificate. See [HTTPS and certificates](HTTPS.md).
  - IP addresses use Let's Encrypt's six-day `shortlived` profile; domains get the standard 90-day certificate.
  - Validation over TCP port 80, opened only for the seconds an order takes, or over Cloudflare DNS for domains (token from a root-only file or `CLOUDFLARE_API_TOKEN`, never an argument). Failures name the cause and the next step.
  - New `gre-manager-panel-certificate.timer` runs `certificate renew` every six hours and renews in the last third of the lifetime (about 30 days before expiry for domains, about two days for IP certificates).
  - New commands `certificate issue`, `renew [--force]` and `self-signed`; `certificate install` (Certbot, acme.sh) now turns built-in renewal off so two clients never compete; `certificate status` adds the renewal record.
  - **Settings → Panel connection security** shows the source and next renewal, a notice after a failed renewal, and the issue command first in its guide. Panel-renewed certificates warn about expiry only when renewal is overdue.
  - New files: `/etc/gre-manager-panel/certificate.json` (public status, no secrets) and the root-only `/etc/gre-manager-panel/acme/` (account key, renewal recipe, DNS token). Panel removal deletes them with the timer.
  - Uses the ACME client in `golang.org/x/crypto`, already a dependency.

- **Terminal menus removed.** Tunnels, forwards and server settings are managed in the web panel; `gre.sh` is its engine. Run without arguments it opens `gtm` (or installs the panel); earlier installer options such as `--quick` still work. `--api` and the read-only `--validate`, `--plan`, `--doctor`, `--catalog` and `--haproxy-status` stay; `--demo`, `--preview` and `--panel` are gone. Saved state, units and peer contracts are unchanged, so existing tunnels keep running. About 1,500 lines of menu, form and header code were removed. See [Command line](COMMAND-LINE.md).
  - The engine never prompts: the caller has already reviewed the change, so `gtm_confirm` succeeds and the per-operation overrides are gone.
  - Retiring a v13.x installation is now two engine operations: `legacy-scan` (read only; one row per item with `ready`, `blocked` and its reason, or `absent`, plus every generated forward group) and `legacy-retire forwards|simple|tuning` or `legacy-retire group TOOL PORT DESTINATION`. See [Retiring old installations](RETIRING-OLD-INSTALLS.md).
  - The `igre` shortcut is no longer a menu; the installer replaces a recognized old copy with a script that opens `gtm`.
  - The [User guide](USER-GUIDE.md) now describes the panel pages; the terminal guide is replaced by [Command line](COMMAND-LINE.md).
- **IP addresses page (Network → IP addresses):** this server's addresses, uplink first, with the saved settings that use each. See [IP addresses](IP-ADDRESSES.md).
  - **IP changed** on one screen: whose address changed (this server or another), old → new with the likely new address suggested, a checklist of every GRE end, connection listen address or destination and reverse-tunnel address that uses the old one, and one Apply. Each item is checked and restored if it does not start; the result is shown per item.
  - When the other end of the GRE tunnels is an online Node with an Agent of v1.6.0 or later, both ends move in one paired job that waits for **Tunnel works — keep** and otherwise returns both sides to the old address. Other peers get the command to run there.
  - A local address that saved settings use but the server no longer has is listed first under **Needs attention** on the Overview, with a link that opens the fix.
  - **Additional IPs:** add an address with its prefix on an interface, optionally with its own gateway (a source rule and table for its replies), and see whether it came up. Each lives in an owned `gtm-addr-N.service` and survives reboots. Removal is refused while something still uses the address.
  - In the command palette: **IP changed** and **Add IP**.
- Broker: `addresses` (read, `GET /api/addresses`), `address-replace`, `address-extra-add`, `address-extra-delete`. Engine: `address-uses`, `address-replace OLD NEW USE ITEM…|all`, `readdress-check`, `readdress-apply`, `extra-list`, `extra-add`, `extra-delete`. Controller: `POST /api/nodes/readdress`; Node task kind `readdress`, gated by Agent version so older Agents and Controllers stay compatible.
- Inventory reports both public ends of each GRE tunnel (`bind`, `remote`).

- **Firewall page (Network → Firewall):**
  - Lists what blocks traffic now, each with a fix: a dropping iptables backend without the owned accept, unloaded rules, closed relay ports under UFW, firewalld.
  - Shows UFW, both iptables backends with their `FORWARD` policy, other nftables tables, the uplink and SSH ports.
  - Per connection: **Open in UFW** adds a rule tagged with the connection ID. It follows port changes, closes with the connection, and is never added when another rule already opens the port.
  - **Access rules** per connection: allow or deny lists of addresses and networks, concurrent connections per source, and new connections per second per source, with drop counters.
  - **Abuse protection:** drops new uplink traffic to private ranges, with exceptions; the gateway, resolvers and destinations are excepted automatically. A separate switch blocks outgoing port 25.
  - Changes can revert themselves unless confirmed (60 s–5 min) through a transient systemd timer on the server.
  - The rules live in the owned table `inet gtm_guard` and settings in `firewall.tsv`, and are reapplied with every kernel apply and at boot. See [Firewall](FIREWALL.md).
- Broker: `firewall` (read), `firewall-apply`, `firewall-confirm`, `firewall-revert`, `firewall-repair`. Engine: `firewall-status`, `firewall-apply SECONDS`, `firewall-confirm`, `firewall-revert`; runner flag `--firewall-revert`.
- **Forwards behind UFW on iptables-legacy:** UFW can keep its `FORWARD DROP` in iptables-legacy while `iptables` is the nf_tables variant. Packets pass both, so the v1.5.3 accept (installed in iptables-nft only) did not help. The owned `GTM_FWD` accept now goes into every backend whose `FORWARD` policy drops. Legacy tables are detected through `/proc/net/ip_tables_names`, so probing never loads legacy modules. The other backend receives the filter accept only; NAT and MSS stay in the default backend.
- **Self-repair after a firewall reload:** `ufw reload` and similar flush `FORWARD`. While a dropping backend exists the refresh timer stays enabled, notices the missing accept and reapplies kernel forwards.
- **Diagnosis:** the forward-policy check names each dropping backend and whether the owned accept is installed there.
- **Server DNS on systemd-resolved:** the engine runs with umask 077, so a `/etc/systemd/resolved.conf.d` it created was mode 0700. resolved reads drop-ins unprivileged, ignored the directory and reported global DNS `none`. The directory is now created world-readable. An unreadable one holding only the manager's drop-ins is repaired; any other is reported, not changed. The boot unit for plain `resolv.conf` hosts is written mode 0644.
- **Phone layout:** the connection editor's step bar stacks each number above its label with a progress line, so no label wraps. Tab lists that may not fit (Traffic, Health, Backups, Maintenance, server details, configuration and advanced connection options) use equal columns on phones, so a tab no longer drops to a second row.
- **Connection check:** a connection's details have a **Check** tab, and saving an enabled connection opens it at once.
  - **Live packet path:** clients → firewall → this server → each destination. It reads the owned rule counters for kernel forwards (new connections, packets and bits per second each way, firewall drops) and open sockets for relays.
  - A verdict names where traffic stops: waiting for traffic, dropped by this server's firewall (with **Fix now**), arriving but not leaving, a destination that does not answer, or only some destinations answering.
  - The guided checks follow below the path.
- **Connection badges:** each card and row shows the address the destination sees (server IP or client IP). Firewall effects link to the Firewall page: forward blocked, closed in UFW, allow or block list, limited.
- **Templates:** a new connection can start from *VPN to a foreign server*, *HTTPS / TLS relay*, *A range of ports*, *Several foreign servers* or, with a GRE tunnel, *Through a GRE tunnel*. They are offered in the editor and in the command palette.
- **Errors that say what to do:** a failed operation shows a plain cause, what to do and, where a page fixes it, a button to that page. Examples: a port in use, changed settings, server DNS, the firewall, a missing engine, an unresolved name, an entrance IP that left the server, a failed configuration check. The engine's message stays under *Technical details*. A failed save is explained inside the editor instead of in a second dialog.
- The Connections page loads on demand like the other pages, which keeps the initial bundle below its v1.5.3 size.
- Broker: `connection-path` (read, `GET /api/connection/path?id=`). Engine: `connection-path ID`, which is read-only.
- **Design system:**
  - A five-step type scale (12, 14, 16, 20 and 28 px) with taller Persian line heights and tabular figures where numbers are compared.
  - Layered surfaces: cards, KPI tiles and list cards share one hairline, soft shadow and, in dark mode, a faint top edge, derived from each preset so preset colors stay exact.
  - **Density** (Comfortable or Compact) in the appearance menu, Settings and the command palette.
  - Latin connection names inside Persian pages keep their own direction.
- **Connection list:** each row starts with a status icon and shows its route on one line (entrance → wire → destinations). The icon and wire share one state: running, needs a look, stopped or blocked, off, or changing. The overview's recent connections use the same row.
- **Live trends:** the overview's CPU, memory, receive and send readings draw a trend line of about the last minute, kept in memory only.
- **Phones:**
  - Dialogs open as bottom sheets with a handle; drag it down or flick to close. The command palette stays at the top so its field is never under the keyboard.
  - Row menus (connections, GRE and reverse tunnels) become an action sheet with large rows.
  - Swipe a connection card for **Turn off/on** and **Edit**, or the other way for **More**. Touch only; delete is never a swipe.
  - The bottom bar's **More** is a sheet with every other page and two quick actions. Overview and Connections show a dot when something needs attention, and the bar slides away while scrolling down.
  - The on-screen keyboard resizes the page, so focused fields in sheets stay visible.
- **Command palette:** a saved connection opens its actions: details, check, edit, turn on or off, duplicate, configuration and delete (with the usual confirmation). Backspace or Escape goes back. Configuration and delete dialogs are now part of the page address.
- **Connections list:**
  - Cards no longer carry a drag handle or an always-visible checkbox, so the header is the status, name and engine only.
  - **Select** (or a long press on a card) turns on selection mode: tap cards to select, **Select all** and Esc in the floating bar.
  - **Reorder** turns the list into compact, numbered rows: drag by the handle, press and hold a row on a touch screen (a short vibration confirms), use the arrow keys on the handle, or the row's ⋯ menu (move to top, up, down, to bottom). Numbers follow the drag live and moved rows are marked. Nothing is saved until **Save order** in the floating bar; **Cancel** puts the list back and the saved toast offers **Undo**. The desktop table lost its handle column.
  - A sort menu (custom order, name, status, engine) is kept in the address; sorting never changes the saved custom order.
- Drag and drop is gone from the overview, GRE and reverse tunnels and Servers, which now keep a fixed order.
- **Connection form:** each step is a few titled cards (Method, Entrance, Name and start; Destinations, Traffic spread, Advanced; Protection, Review). The method is chosen from cards with one line each, templates are one row of chips (a sideways row on phones) with the chosen template explained under it, and an engine with one protocol shows it as fixed instead of a one-button toggle. Fields side by side line up (every label row has one height), **Name** is marked *Optional* in a quieter weight, and **Next** names the next step. A field that fails shows its reason under it; with two or more, a summary at the top links to each. The route map and summary bar say *No port yet* instead of a dash.
- **Connection form, destinations:** with two or more, each destination is a compact numbered row (address and port, share, domain check) that opens to edit; a row that is not complete stays open. With primary + backup the first row is marked **Primary** and the rest **Backup**. The order changes by the handle or the row's ⋯ menu, which also removes it.
- Fixed: the reorder list's sticky header covered its first row, so one connection seemed missing; on phones a row's ⋯ button inside the connection form submitted the step.
- The connection table no longer renders drag-and-drop helper elements inside `<table>` (a React warning in the console).
- Local evidence:
  - Python unit suite, including mode checks on ext4, the firewall engine with UFW, nft and systemd stubs, and the packet path parsing nft, iptables-save and `ss` output.
  - Go race tests, ShellCheck, and web build, lint and tests.
  - `tests/linux_namespace.sh` in WSL:
    - a real iptables-legacy `FORWARD DROP` next to iptables-nft;
    - allow/deny lists and private-range blocking with real TCP traffic through `inet gtm_guard` (nft 1.1);
    - the packet path reading real nftables, iptables and guard counters after real traffic.
  - In the demo, in both locales at phone and desktop widths:
    - the Firewall page;
    - the Check tab;
    - templates;
    - badges;
    - the explained port-conflict error;
    - the status icons, route chain, density and live trends in light and dark mode, with no horizontal overflow at 375 px and named controls on every page;
    - bottom sheets with drag-to-close, the action sheet, card swipes in both directions (RTL and LTR, with synthetic touch input), the More sheet, the hiding bottom bar and the palette's connection step, plus unchanged desktop menus and centred dialogs. Real phones (iOS Safari, Android Chrome) remain to be checked by hand.
  - Deployment checks still needed: real UFW hosts, `ct count` limits under load, a real systemd-resolved restart, and relay socket counts under real clients.

## v1.5.3 — Forwarding on multi-address and Docker/UFW hosts, server DNS ordering

- **nftables forwards behind Docker/UFW:** both set the iptables `FORWARD` policy to `DROP`, which an accept in the manager's nftables table cannot override, so nftables forwards silently stopped (iptables forwards were unaffected). When iptables is installed, nftables forwards now also get scoped accepts in the owned `GTM_FWD` chain. A namespace packet test covers TCP/UDP through an nftables forward under `FORWARD DROP`.
- **Multi-address uplinks and IP changes:** kernel `masquerade` used the first address of the egress interface, not the route's preferred source. With an additional/floating IP or an old address still assigned, the destination (a VPN server abroad, for example) answered an address that never returned here. Forwards that masquerade now SNAT to the route's preferred source when the egress interface has several global IPv4 addresses; single-address hosts keep masquerade. The refresh timer reapplies kernel rules when those sources drift.
- **Server DNS on systemd-resolved:** the managed drop-in is now `zz-gre-manager.conf`, so named drop-ins such as `dns.conf` no longer override it (the cause of "The resolver did not activate the selected DNS servers"). The old `90-gre-manager.conf` is migrated. Verification waits for resolved to settle, accepts `resolvectl` port/interface/TLS-name suffixes and names any overriding drop-in.
- **Diagnosis:** kernel connections report the entrance address (fails when a specific listen IP left the server), the `FORWARD` policy with the owned accept, and the source address the destination sees. The terminal diagnostics note is updated.
- **Panel addresses:** server addresses list the default-route interface first and container bridges last. Pairing defaults to the saved public IP only while it is still assigned, otherwise to the uplink's IPv4 address, so a changed server IP no longer pre-fills a GRE source that preflight rejects.
- Local evidence: Python unit suite, Go race tests, web lint/tests, ShellCheck and `tests/linux_namespace.sh` in WSL namespaces (nftables 1.1.6, iptables-nft 1.8.11). Real Docker/UFW hosts, provider additional IPs and a real systemd-resolved restart remain deployment checks.

## v1.5.2 — Reliability, certificate renewal and responsive workspace

- Rename the owned nftables MSS chain to the non-keyword identifier `gtm_mss`; some parsers reject `mss` and quoted identifiers. Saved records and peers are unchanged.
- Initialize boot runners for port ranges and multi-answer DNS. Refresh validates resolved endpoints, rejects self-loops, retains pending reconciliation after failure and applies policy changes immediately.
- Server DNS resets inherited systemd-resolved lists, verifies active global servers where supported, recovers prior files on failure and distinguishes active, configured and local-stub addresses.
- Update the closed panel-removal manifest for current owned state and scheduled snapshots. Unknown files/links stay protected; pending Safe Apply or an active optimization watch blocks removal.
- Bind Safe Apply to exact mutation receipts; order new restore points with a locked monotonic sequence, with write-time fallback for legacy names; retain failed rollback with bounded retries and visible recovery errors.
- Add external certificate installation for Certbot/acme.sh, validated private bundles, SIGHUP reload, explicit HTTP-to-HTTPS conversion and bilingual certificate status. See [HTTPS](HTTPS.md).
- Preserve domain DNS policies in portable backups, read historical archives without that optional field, exclude domains from IP migration and clarify local snapshots versus downloaded recovery.
- Reveal hidden invalid advanced fields; prevent duplicate submission after a saved connection's DNS-policy failure. Distribution counts use resolved backends.
- Recognize interrupted `.panel-<digits>` / `.tls-<digits>` writes only in their owned private directories during panel removal; unknown files and symlinks remain blockers.
- Organize Settings into Security & access, Appearance, Notifications and Metrics tabs with history/bookmark support and retained in-memory drafts. Move optional DNS guidance into hover/focus/tap help.
- Reflow destination editing by available card width; separate ordering/actions from address fields, align labels and numeric inputs, compact the phone step header/footer and protect endpoint port digits from wrapping.
- Verify responsive geometry in both locales; real CA renewal, VPS reboot and real DHCP/resolver validation remain deployment checks.

## v1.5.1 — Package license notice

- Panel packages now include the MIT license notice of dnd kit (`LICENSES/DndKit-MIT.txt`), the drag-and-drop library added in v1.5.0, and `NOTICE.md` names it. No functional changes.

## v1.5.0 — Port ranges, domain destinations, server DNS and a new connection editor

### Panel

- **Connection editor** in three steps — Entrance, Destinations, Protection & review — beside a live route map (ports → this server → destinations, what a domain resolves to, monitoring and safe apply). Steps validate before moving on; finished steps can be reopened; on phones the map folds into the summary bar.
- **Port ranges and mapping:** a range such as `2000-2999` is one nftables/iptables record and rule (up to 4096 ports). Remote ports: *Same port*, *One port* or *Mapped* (`2000-2999 → 3000-3999`, nftables), with a live preview. Search finds a port inside a range.
- **Domain destinations:** an address field takes a domain, checks it as you leave it and shows its addresses; refresh interval (1–60 min) and *all addresses / only the first* per name. Rules use the cached addresses; a refresh changes rules only when an address changes.
- **Health and protection in the forms:** connection and GRE forms show whether health checks are on (one switch turns them on), and set *Monitor this connection*, *Automatic failover* (kernel forwards with two or more destinations, domains included) and *Notify me*. GRE cards get the same choices from a shield button. Lists show a health dot per row.
- **Safe apply:** a change can revert itself after 2, 5 or 10 minutes unless confirmed; a banner counts down with *Keep changes* and *Revert now*. The server reverts on its own (through the change history) only if nothing else changed meanwhile, and sends a notification.
- **Drag and drop** with a handle (mouse, touch, or arrow keys on the focused handle; announced to screen readers) for connections, destinations (failover priority), GRE and reverse tunnels, Nodes and the Overview blocks. List order is saved on the server for every device and never changes configuration.
- **Duplicate** a connection onto the next free port or range.
- **Optimization → DNS** tab: international and Iranian presets or manual servers, a speed test from the server, apply that survives reboots and DHCP, and restore of the original. See [Port ranges, domain destinations and server DNS](PORTS-AND-DNS.md).
- **Import from Port Forward Manager** (portfw / portfw-nft) on the same server, with range and mapping conversion.

### Server and tooling

- `state.sh`/`firewall.sh`: range ports and one-to-one target ranges (`gtm_port_span`, `gtm_target`), range-aware listener conflicts, nftables port maps, iptables `--dport A:B`, range-aware flow reset. Strict legacy parsers keep `gtm_endpoint`.
- New modules: `resolve.sh` (DNS cache and policy, expansion, `--dns-refresh` timer), `sysdns.sh` (server DNS for systemd-resolved and plain resolv.conf; Tools → Server DNS), `portfw.sh` (rule export and listener guard).
- Terminal forms accept ranges for kernel engines, mapped remote ports (nftables) and domain destinations.
- Broker: `dns`, `dns-test`, `dns-resolve`, `dns-apply`, `dns-restore`, `dns-policy`, `dns-refresh`, `ui-order`/`ui-order-save`, `change-pending`/`change-confirm`/`change-revert`, `health-protect`; health settings gain `ignore` and `quiet`; notification kind `change-reverted`.
- New files: `/etc/gre-manager/dns-cache.tsv`, `dns-policy.tsv`, `dns/`; `gre-manager-dns.{service,timer}`; `gre-manager-resolv.service` with `/usr/local/lib/gre-manager/resolv.sh` or `/etc/systemd/resolved.conf.d/90-gre-manager.conf`; `/var/lib/gre-manager-panel/ui-order.json` and `safe-change.json`.

Local evidence only: Python, Go (race, vet) and frontend tests, ShellCheck, `nft -c` and `iptables-restore` of range rules in an isolated namespace, and browser checks of the demo in both languages at desktop and phone width. Not yet run on real servers: domain refresh against changing records, server DNS on real systemd-resolved/DHCP hosts and an import from a live portfw installation.

## v1.4.1 — Notifications, change history, scheduled backups and tunnel tests

### Panel

- **Notification center:** a bell in the header lists outages and recoveries, failover changes, automatic undo, maintenance results and scheduled backups, grouped by day with unread counts; selecting one opens its page. **Settings → Notification channels** sends chosen kinds to a webhook (JSON, optional HMAC-SHA256 signature) and a Telegram bot (optional Bot API relay), in English or Persian, with retries, a rate limit and a test button. Secrets are stored root-only and never shown again. See [Monitoring](MONITORING.md).
- **Change history** (new page): every forwarding change as a day-grouped timeline with what changed per connection (added, removed, or which fields). **Restore to before this** reviews exactly what restoring changes now and restores through the normal apply path, saving the current state first so the restore is undoable too.
- **Scheduled backups** (Backups → Schedule): daily or weekly recovery snapshots on the server in the maintenance time zone, the newest 1–60 kept, optional traffic history, **Back up now**, delete, and download of any snapshot as a password-protected `.gtm-backup`.
- **Diagnose:** a read-only "why isn't it working?" checklist for connections and GRE tunnels (Health details, connection and GRE menus) with problems first and a fix for each.
- **GRE quality test:** 20 pings through the tunnel with latency, jitter, loss and a per-ping chart.
- **Far-side checks and speed tests through Nodes:** v1.4.1 Agents report their load and whether each GRE peer answers from their side; Health shows "Far side ✓/✗" beside local tunnels and Node details offer a TCP speed test through the tunnel in both directions.
- **Metrics export (Prometheus):** an opt-in `/metrics` endpoint with a bearer token shown once.
- **Optimization:**
  - Redesigned as a control center: a progress ring, the profile as a three-stop intensity and icon goal cards, the server facts and the actions in one card; groups and the safety/history/files column below.
  - **Apply all** reviews and applies every group with changes at once.
  - **Profiles:** an intensity level (Conservative, Balanced, Aggressive) and a goal (General, Many users, Low latency). Balanced · General is the default and equals v1.4.0. Aggressive is capped to Balanced table and buffer sizes below 2 GB of memory. Moving between profiles compares against each key's original value, so a lighter profile lowers what the panel raised but never below what the server had.
  - **Custom values** within safe bounds in the review, with an explicit confirmation for values worse than the original.
  - A **Network card** group: transmit queue length and packet steering (RPS) across every CPU for single-queue cards, replayed at boot by a small unit.
  - **Automatic undo:** watch tunnel health for 5–60 minutes after an apply and undo the step if a healthy connection goes down; the page shows a countdown and the outcome, and a notification is sent.
- The Optimization uplink fact, Health quality and far-side texts, and every new screen are bilingual with Latin digits, keyboard accessible and fit a phone screen.

### Server and tooling

- New engine modules: `history.sh` (`history [LIMIT]`, `history-restore POINT REVISION`) and `diagnose.sh` (`diagnose ID`), both behind the existing API and lock.
- `optimize.sh`: profiles from `GTM_OPT_LEVEL`/`GTM_OPT_GOAL`, `net.ipv4.ip_local_port_range` (never over a listening port) and `net.ipv4.tcp_max_tw_buckets` for Many users, custom-value bounds, link keys `link.IFACE.txqueuelen` and `link.IFACE.rps` for the uplinks of the default routes (an existing RPS mask is kept), `/usr/local/lib/gre-manager/optimize-links.sh` with `gre-manager-optimize.service`, and the terminal menu's **Network card** and **Change profile**. Reading a key no longer starts a subprocess for whitespace.
- Broker: a bounded notification worker, health transition events, the optimization watch, a snapshot scheduler, `/metrics` token checks, the GRE quality test, and `node-probes` on the read-only Agent broker.
- Nodes: optional `POST /v1/probes` sideband (probe protocol 1) with speed-test offers in its acknowledgment; Agent flag `--probes` (default on).
- New private files under `/var/lib/gre-manager-panel`: `notifications.json`, `snapshots.json`, `snapshots/`, `prometheus.json`, `optimize-watch.json`. See [Server artifacts](ARTIFACTS.md).

Local evidence only: Python, Go (race, vet) and frontend tests, ShellCheck, and browser checks of the demo in both locales at desktop and phone width. Not yet run on real servers: boot replay of link settings, speed tests between two VPSs, far-side checks through real firewalls and delivery through real webhook/Telegram endpoints.

## v1.4.0 — Failover, server optimization and a leaner terminal

### Panel

- Add **health failover** for nftables and iptables forwards with several destinations, off by default and chosen per forward. Their destinations are probed every 5 seconds (2–30 s); a destination that is down stops receiving new connections, its tracked flows are cleared so clients reconnect to a live one, and it returns when it answers again. At least one destination always stays, the saved configuration is unchanged and a reboot, an edit or turning monitoring off restores every destination.
- HAProxy destinations on **Health** use HAProxy's own check results (status, check time, active sessions, backup) from its stats socket instead of a second probe.
- Expanded Health rows show the 24-hour share of failed checks, new connections per destination for balanced nftables forwards, and an on-demand **path MTU test** for GRE links with a suggested MTU.
- Add an **Optimization** page with four opt-in groups designed for tunnel and forwarding servers: Connection tracking (memory-sized flow limit, hash buckets at half the limit, 1-hour idle TCP, 30-second closing states, 60/180-second UDP), Packet queues, Relay TCP (BBR, fq, 32 MiB buffers, 128 KiB unsent data, MTU probing, keepalives inside the tracking timeout) and Tunnels & routing (loose reverse-path filter, no ICMP redirects). No recommendation is ever worse than the server's live value, including the provider's defaults: limits only grow, timeouts only shrink, buffer triples grow per field, equivalent choices such as `cake` or `bbr2` stay, and those keys are shown as kept. The page summarizes improvements for this server, marks groups that fit what it runs, reviews them together and lists each setting with its current, recommended and original value. Undo goes back step by step (20 steps), Restore originals undoes one group and Reset everything returns every value and deletes the panel's files. ServerTools and other drop-ins that set the same keys are detected and shown; the panel's drop-in sorts last and wins at boot.
- Health → Server hints link to the Optimization page instead of an external tool.

### Server and tooling

- Replace the old tuning module and its profiles with `optimize.sh`: a new journal (`/etc/gre-manager/optimize/`), `zz-gre-manager-optimize.conf`, a module list that loads `nf_conntrack`/`tcp_bbr` before sysctl at boot, undo steps and per-group restore. Tuning applied with v1.3.7 or earlier is imported on the first change and stays resettable.
- Add Bash API operations `forward-exclude ID LIST|-` (runtime-only exclusions under the manager lock, then a kernel reapply and a flow reset limited to newly excluded destinations) and `optimize-status|plan|apply|undo|remove`.
- Balancing chains of nftables forwards count new connections per destination.
- Remove the v13.x scripts (`gre-stable.sh`, `legacy/`), `src/legacy.sh` and the old numbered menu (`--legacy`). The terminal creates and deletes GRE through the same engine as the panel; **Tools → Retire old installation** keeps the recognized removal of v13.x forwards, Simple GRE and old tuning files. GRE tunnels created by old versions keep working.
- AGENTS.md now states the kernel-first and thin-menu rules.

Local evidence only: Python, Go and frontend tests plus browser checks of the demo in both locales and at phone width. Failover, flow counts, the MTU test and boot-time optimization have not yet been run on a real server.

## v1.3.7 — Health monitoring and scheduled maintenance

### Panel

- Add an optional **Health** page, off by default. On a configurable interval (default 30 s) it checks every enabled destination with one TCP connection (ping for UDP-only services), GRE peers over the tunnel and managed service units. It shows current status, latency sparklines, 24 h / 7 d / 30 d uptime with hourly and daily cells, an outage history and a weekly report (CSV and print) with downtime, latency, jitter, server load, maintenance runs and accounted traffic. Thresholds, slow-latency warning and retention (1–90 days) are configurable.
- Show server pressure on **Health → Server**: conntrack usage, hash buckets, idle-TCP timeout and drops, and CPU steal, softirq and I/O wait, read from `/proc` and `/sys`. Hints point to ServerTools for tuning; the panel changes no kernel settings. This explains the common case of ping and jitter that rise over hours and clear after a reboot.
- Add an optional **Maintenance** page, off by default, with plans for a soft refresh (reapply kernel rules, reload HAProxy gracefully; no disconnects), a restart (services, GRE links, reverse tunnels; for kernel forwards, clearing only that forward's tracked flows) or a server reboot. Triggers: daily, weekdays, every N hours, after long uptime and health conditions (down or high latency for N minutes, acting only on affected tunnels). Guards: time window, quiet-traffic wait, cooldown, daily limit, cancellable notice, pause between tunnels, reboot loop guard and dry run. Six templates, Run now, pending countdown with Cancel, and history. Enabled reboot plans need a second confirmation.
- The dashboard's live activity refreshes every 2 seconds by default, with 1, 2, 5 and 15 seconds selectable and remembered per browser. The server-side sample cache drops from two seconds to under one.

### Server and tooling

- Add Bash API operations `kernel-refresh` (reapply owned kernel rules from saved state under the manager lock) and `flows-reset ID` (delete the conntrack entries one kernel forward DNATed to its own targets; never a table flush). They require the `conntrack` CLI for flow resets.
- The broker keeps health and maintenance state in root-only `health.json` and `maintenance.json` under `/var/lib/gre-manager-panel`. No unit, timer, firewall rule or daemon is added; Agent brokers do not run either feature.
- Namespace tests show that a rule refresh keeps established flows and a flow reset clears only the selected forward. CI installs `conntrack`. Local evidence only; long-running behavior and real reboots were not tested on a server.

## v1.3.6 — Return routing for additional IPs with their own gateway

### Server and tooling

- Fix kernel forwards on additional IPs that have their own gateway (source policy routing such as `ip rule add from X lookup N`). Forwarded replies are routed before un-DNAT, so they skipped that rule, left through the main gateway and were dropped by provider anti-spoofing. Apply now finds each address's table with a packet-free route lookup. Flows entering on such an address get a connection mark (bits `0xf000000`), and an owned `fwmark` rule at preference 31001-31015 routes their replies through that table. Both iptables and nftables are covered. Hosts without per-address tables render exactly as before, and the rules are reconciled at boot and removed with the last kernel forward.
- Allow IPv4 and IPv6 kernel forwards on the same port. Their rules never overlap, but the loader rejected `0.0.0.0` beside `::` (or beside a specific IPv6 address) as a conflict. Relay/kernel pairs still conflict, because a relay on `::` can accept IPv4.
- `--doctor` lists addresses with their own routing table and their return-rule state, and warns about strict `rp_filter` on those interfaces. It also names explicit-bind kernel forwards on hosts with other addresses of that family, such as records saved before v1.3.5. Saved records are not changed.
- Namespace tests now cover IPv6 additional addresses (nftables and ip6tables), dual-stack listeners on one port, and a policy-routed address with modelled upstream anti-spoofing, including removal of a stale return rule. Local test evidence only; no real provider network was used.

## v1.3.5 — Additional-IP forwarding, reliability fixes and a redesigned panel

### Panel interface

- Add three project presets, all at WCAG AA in both modes (checked by `tests/themes.test.mjs`): **Signal** (Grafana-like, the new default), **Graphite** (Linear-like) and **Aurora**. Nettinx and Neutral stay selectable and unchanged. Browsers whose stored preference was the old automatic Nettinx default move to Signal once; later choices are kept.
- Set Latin text and digits in self-hosted Inter, with Persian falling through to Vazirmatn, so mixed Persian/English lines share one rhythm. Persian keeps taller lines and no letter spacing.
- Merge the Port forwarding, HAProxy and Realm pages into one **Connections** page with engine filter chips and counts. Old `#/forwarding`, `#/haproxy` and `#/realm` links open the matching filter and are rewritten to the new address.
- Regroup the sidebar into Workspace, Network and System, and add a search entry. Add a **Ctrl/Cmd+K** command palette for pages, filters, saved connections, creation per engine and appearance.
- Rebuild the overview around status: host and address, four KPI tiles, live telemetry beside a **Needs attention** list (failed or stopped enabled services, missing engines) and recent connections with engine shortcuts. Remove the duplicated address chips and the marketing headline from the workspace.
- Replace the ambiguous square stop icon with an explicit on/off switch per row; configuration moves into the row menu. Bulk actions appear in a floating selection bar, above the bottom navigation on phones.
- Show presets as cards with light and dark miniatures in Settings, and put mode and preset together in the header's appearance popover. Add a two-step indicator and the engine glyph to the connection form header; drop its address chips, which took about 100 px on phones. Put the connection search on its own row on phones so its placeholder is no longer cut off.
- Add subtle motion (staggered page entry, hover lift, live pulse, selection bar) that is removed under reduced motion.
- Keep the demo sign-in hint after signing out of the demo, and fix the destructive alert's text contrast.

### Frontend structure

- Move session, inventory, job and preference state out of `App.tsx` into hooks; validate and migrate preferences in `lib/preferences.ts`.
- Share one `usePoll` hook for every periodic request (visibility, no overlap, abort and timeout), replacing five copies, and rename state setters that shadowed `window.setInterval`.
- Split the 1,400-line message file into feature modules type-checked for both languages; tests enforce one owner per key and Latin digits in Persian text. Unknown keys no longer resolve through `Object.prototype`.
- Split the stylesheet into base, shell, components, forms and motion layers. Share the navigation model between the sidebar, mobile bar and palette, and move list filtering and attention rules into tested framework-free modules.
- Let the Vite dev server proxy the API to `gtm-panel demo` while keeping the panel's Origin/CSRF checks intact.

### Server and tooling

- Fix iptables/nftables forwards on servers with additional IPs. Kernel rules previously matched one destination address, and the panel defaulted to the first IPv4 the OS listed, which could be a secondary, private or GRE address. New kernel forwards default to all local addresses (`0.0.0.0` / `::`). Rules then use `fib daddr type local` (nftables) or `-m addrtype --dst-type LOCAL` (iptables). Explicit binds keep their exact match, and the panel suggests this server's addresses. Wildcard records conflict with any other listener on the same port and protocol. Preflight rejects a wildcard DNAT back to this host's own port. Saved records are unchanged. Older releases reject wildcard kernel records, so a downgrade needs a compatible restore point.
- Replace the owned nftables table atomically in one batch instead of flushing it. Balancing chains of deleted records or removed targets no longer accumulate. The table is removed when no nftables forward remains. Existing flows keep their conntrack NAT mappings.
- Reject IPv6 spellings with a stray single colon (`:1::2`, `1::2:`). The validator previously accepted them, and the address key then failed with an arithmetic error.
- Load state in linear time with no per-address subshells. 300 records went from about 20 s to 0.4 s on a Windows test host. Inventory, edits and commits all load state.
- Keep the newest 100 automatic forwarding restore points (`GTM_RESTORE_POINTS`; `0` keeps all). Cleanup, tuning, legacy and manually named files are never pruned.
- Start or reload changed HAProxy/Realm services after one `systemd` reload per apply. Wait for a Realm TCP listener and detect early exits instead of a fixed one-second sleep. Share one WSS gateway unit renderer between terminal setup, the API and recovery.
- Serve broker reads (inventory, metrics, telemetry, configuration review, engine releases) without the mutation lock, with bounded concurrency. Dashboards stay responsive during a long apply or package installation. One action registry now drives the public allowlist, broker locking, audit filtering and backup routing.
- Keep the panel broker running independently of the public panel, so traffic sampling and opt-in quota pauses continue while the panel is stopped or restarting. Roll back to the previous panel executable and helper when an upgraded panel fails to start.
- Count failed logins per IPv4 address or IPv6 /64, and evict the oldest entry when the table is full. Many failing clients can no longer lock the administrator out. An expired session no longer echoes its CSRF token.
- Keep polling a running job through temporary network, gateway or busy-panel errors (bounded backoff) instead of reporting it failed. Report the HTTP status when an error response is not JSON.
- Check every release version copy (Go, frontend, package and installers) against `src/core.sh` in `tools/build.py --check`.
- Make previously vacuous tests enforce their checks: state-loading conflict tests fed a pipe the loader rejects, and negated namespace-test commands never failed under `set -e`.

## v1.3.4 — Traffic controls, live telemetry and clearer configuration workflows

- Show numeric cycle quotas, progress and applied traffic-pause state consistently on desktop/mobile accounting views.
- Add explicit opt-in quota pauses using owned nftables drops for both directions, including established flows; cycle reset/limit edits release guards. Detection remains sampled. Existing policies stay advisory; portable restore disables pauses.
- Add on-demand dashboard CPU, memory and default-route network rates with visible-only 5/15-second polling, a shared cache and no extra daemon or disk history.
- Document which dataplanes run in Linux and which rely on resident userspace engines.

- Repair mobile connection identity wrapping and destination disclosures. Restore direct start/stop and configuration actions beside edit; compact search/filter placement, balance desktop columns, collapse mobile appearance controls and add useful footer shortcuts without changing Nettinx colors.
- Open supported configuration text editors directly. Fix real HAProxy `targetN` server edits, consistent repeated caps, target additions/removals and optional directive removal. Add strict single-destination iptables/nftables text edits with full companion-rule round trips; never execute submitted firewall text.
- Add reviewed, additive imports from pasted/uploaded HAProxy TCP configurations, simple Realm TOML and managed JSON objects/arrays for all four forwarding engines. Show replaced process settings, reject unknown/lossy syntax and changed reviews, preserve unrelated state under the shared lock, and save paused unless explicitly activated.
- Default new HAProxy connections to automatic native connection sizing, no per-server cap, traffic logs off and active checks off. Preserve saved/legacy defaults. Allow explicit caps and affinity tables up to 1000000; retain finite connection/inactivity timeouts. Presets explicitly enable TCP checks and reset stale advanced options.
- Add manual official release checks and confirmed engine maintenance. Keep verified binary pins separate from latest upstream releases; use reviewed distribution candidates for system packages and retain old pinned binaries for recovery.
- Recognize the official capitalized Realm version/build-feature output in inventory and staged-binary verification.
- Add local FRP KCP transport, UDP listener checks, native verification and backup round trips. Existing Node pairing retains its TCP/WS/QUIC capability contract.

## v1.3.3 — Refined workspaces and encrypted portable recovery

- Add an optional local-server Backup & restore workspace with encrypted downloads, source/destination review, IP/interface migration, explicit conflict checks and paused recovery on a fresh installation. Preserve managed forwarding/GRE/reverse definitions, reverse secrets, display names, allocation counters and optional traffic records; keep panel/Node identities and external host resources separate.
- Stage and validate typed recovery records behind the local broker and shared Bash lock. Reject stale reviews, unknown schemas and occupied targets; report partial accounting persistence. Share the GRE unit renderer between normal creation and recovery.
- Add a persistent-start action for managed GRE/reverse services so restored resources can be explicitly started and enabled for boot from the panel.
- Keep long inline help within the available viewport, with scrollable popovers and compact mobile backup guidance.

- Redesign the connection workspace around entrance/destination panels, separate basic/advanced tabs, optional names, a route summary and review before save. Split draft state, common fields, engine settings and review into separate modules; retain saved configuration semantics.
- Add shareable hash routes with browser history, URL-backed connection search/status/detail state and direct links to selected traffic details. Keep embedded-server/API paths unchanged.
- Replace crowded row actions with direct edit and a labeled menu. Add per-connection summary/destination inspection, separate server/paired-connection tabs and a compact dashboard metrics band. Move the whole-server configuration preview to the page toolbar.
- Introduce a shared server-information header, typed notifications above mobile navigation, and discard protection for changed connection, GRE/reverse and configuration drafts. Lazy-load editors and resource setup; no server-side service or build-tool requirement is added.
- Fix address, configuration, command, enrollment-code and reverse-token copy buttons on HTTP pages. Prefer the Clipboard API, fall back to a user-initiated selection copy inside the active dialog, restore focus/selection and report success or a manual-copy instruction without exposing secrets in notifications.

## v1.3.2 — Compact forms, simpler setup and refreshed documentation

- Fix nested modal scrolling and hidden Radix form controls escaping the scroll body. Keep headings/actions visible and use compact responsive field groups.
- Simplify the web catalog to three short setup presets per engine; retain the other supported advanced settings.
- New HAProxy connections use a 100000 connection ceiling, no per-target cap and logs off. New Realm connections start with logs off. Preserve all saved records and legacy absent-key semantics; explicit user values win.
- Route Add server to a three-step setup guide when the optional Controller is disabled. Keep browser HTTP independent of the TLS Agent listener and show readable installer commands.
- Add a paginated all-connections traffic tab with per-row quota/reset/stop actions and separate details/history. Keep missing samples unavailable.
- Label address families separately, explain relative connection share and start-after-save, and clarify the read-only whole-server preview. Preserve the selected palette and reduced-motion support.
- Correct simulated connection revisions after ID assignment and enable/disable so new Demo records remain inspectable; keep disabled Demo status consistent.
- Rewrite English/Persian quick starts, simplify contributor instructions, add a release checklist and separate historical milestone reports from current guides.

## v1.3.1 — Configuration workflows, VPN profiles and multi-server management

- Correct RTL alignment, container-responsive tables/cards, mobile forms, Latin display digits and dashboard density.
- Add local configuration inspection, copy/download and supported JSON/native editing with revision checks, validation and recovery. GRE/reverse file views remain read-only; reverse secrets are masked.
- Add 23 starting profiles and bounded HAProxy FIN/tunnel/retry controls, IP affinity, TLS/SNI/HTTP routing, Realm WS/MPTCP/IPv6-only options and nftables selection methods.
- Add quick/custom HTTP/HTTPS installation, automatic addresses/ports, generated credentials and upgrade preservation.
- Add optional outbound mTLS Agents, the local Node, coordinated leased GRE/FRP creation and opt-in read-only remote traffic summaries.
- Add local traffic cycles, labels, resets, advisory quotas, bounded optional history and CSV export.
- Add engine/version discovery, independent GRE/reverse display names, guarded panel removal and scoped ownership/recovery checks.

Completed phase reviews and their verification evidence are preserved in the [archive](archive/README.md). This release consolidates those milestones; it does not add unrestricted remote edits or automatic quota cutoffs.

## v1.3.0 — Optional Go web panel

- Add an optional self-contained Go HTTPS panel with an embedded React/shadcn frontend, Persian RTL/English LTR, mobile navigation, the original user-selected Nettinx palette and a neutral alternative. Keep terminal styling independent. Document the preserved theme's known contrast failures.
- Install through the main menu or a separate one-line installer, with a selected/random free persistent port and user-created bcrypt credentials. Run public HTTP as `grepanel`, delegate closed operations over a group-protected Unix socket, enforce sessions/Origin/CSRF/login limits and bounded jobs, and record action-only audit metadata. Provide self-signed IP certificates and local credential recovery.
- Add a noninteractive Bash API using full-state locks, row revisions, existing preflight/snapshots/recovery, bounded batch creation and grouped changes. Add GRE and FRP/rathole adapters preserving wire/config contracts and unrelated resources. No arbitrary shell, file or native-config editor endpoint.
- Expose existing managed HAProxy TCP controls and presets. Add bounded Realm timeouts, keepalive/probes, PROXY and log controls in state v3; preserve existing v1/v2 and keep v3 options across terminal edits. Older releases cannot load v3.
- Add optional nftables entrance/forward counters and GRE interface samples, per resource/port, configurable sampling, checkpointed totals and disable cleanup. Never treat NAT-chain first-packet counters as flow volume or combine overlapping GRE/forward totals. Document reset/offload and billing limitations.
- Add optional engine preinstallation, suppress newly installed distribution HAProxy autostart, preserve existing service policy, and ship prebuilt amd64/arm64 packages with checksums. Add Go, HTTP security, API and actual namespace accounting checks. Tunnel engines remain independent of panel processes.

## v1.2.3 — Server identity banner

- Redesign menu headers with an adaptive ASCII GRE banner, dedicated engine title, version, host/OS and complete copyable IP addresses. Use a compact header on short/narrow terminals; keep fixed foreground colors and no-color fallbacks.
- Show outgoing public and assigned local addresses separately, including IPv6 when available, plus approximate network provider, ASN and country. Display metadata never changes network setup defaults.
- Collect local information without route probes and use one optional two-second HTTPS lookup per interactive session. Keep data/failure cached in memory, sanitize external text, and fall back to local addresses when offline. No new files, packages or background processes. Add Tools → Refresh Server Info and `GTM_SERVER_LOOKUP=0` to skip the request. Previews/demo/inspection/noninteractive output remain free of external lookups.
- Redisplay the header at interactive setup steps and before the GRE wizard. Update both READMEs and terminal/development guides.

## v1.2.2 — Dedicated managers and port-first setup

- Replace appearance preferences, themes, dark/light modes, layouts and Farsi/Finglish terminal guides with a fixed foreground-only ANSI palette and English UI. Keep NO_COLOR/non-TTY/dumb fallbacks. Ignore old preferences without deleting them; remove their CLI switches.
- Give HAProxy and Realm dedicated headers and managers for add/balancing/list/edit/delete, start/stop and scoped status, recent logs and checked restart. Simplify HAProxy advanced settings and use numbered PROXY/log choices.
- Add a forms module: local ports first, separate remote IP and port with IP:port acceptance, automatic optional names, numbered protocol/balancing/transport choices, immediate input retry and review before resources change.
- Accept up to 32 unique local ports/ranges per setup, with fixed or matching remote-port mapping. Create independent schema-compatible records, allocate unique monotonic IDs and perform one full-state commit under lock. Preserve edits, disabled state, source policy, advanced options and stale-edit protection.
- Default relays to all IPv4 addresses and suggest a specific kernel local address from a read-only route lookup. Show listen scope in review; reject wildcard relay loops to a local listener during preflight.
- Stage FRP/rathole ports and peer details before confirmation/install, with numbered protocol/transport/mux choices and default names. Keep existing protocol/security contracts.
- Provide English README.md and RTL Persian README.fa.md with reciprocal links. Rewrite setup guides; make CLAUDE.md contain only @AGENTS.md and keep AGENTS.md canonical. Preserve the historical archive and frozen stable script.

## v1.2.1 — Terminal presentation and simpler getting started

- Simplify the actual Bash interface into seven named sections: GRE Tunnel, Port Forwarding, HAProxy Tunnel, Realm Tunnel, Reverse Tunnel, Load Balancing and Settings & Tools. GRE uses direct Kharej/Iran setup; retain original legacy numbering separately. Keep labels short and move optional source/interface choices behind an advanced prompt.
- Add bounded panels, Guided descriptions/Compact labels, consistent row backgrounds and distinct 256-color/ANSI fallback palettes. Keep plain/no-color output and ASCII fallback; no web panel or new required runtime dependency.
- Detect SSH terminal dimensions when available, constrain panel widths and adapt descriptions to smaller windows. Render connection cards without truncating technical endpoints. Preserve all menu actions and legacy numbering.
- Save a validated layout preference and add `--layout guided|compact` for session overrides. Technical labels remain ASCII; Farsi guides remain outside fixed-width panels.
- Scope HAProxy/Realm/kernel list, edit, delete and enable/disable selections to their section, then reload the complete state under lock so unrelated engines are preserved.
- Keep the supplied legacy code archive unchanged and rewrite its README with correct legacy download paths, menu reference and the old shortcut's current-version download behavior.
- Rewrite the Persian README around a clear download/run command and three-step start. Move the detailed reference to USER-GUIDE.md and add TERMINAL-UI.md explaining the HTML prototype, actual terminal behavior, old copies and appearance troubleshooting. Present v1.2.1 as a regular release; retain operational limits in the reference docs.

## v1.2.0 — HAProxy controls and scoped legacy operations

- Extract a dedicated HAProxy module; add bounded per-connection connect/idle/queue timeouts, connection caps/FD budgets, health-check intervals/timeouts/fall/rise/alternate ports, slow start, consistent source hashing, log levels and opt-in PROXY v1/v2.
- Add backward-reading v2 HAProxy records with validated options. Preserve settings during edits, enable/disable and restore. Older managers cannot read v2 rows.
- Add a staged settings UI, long-lived preset and bounded read-only `--haproxy-status ID`; private Unix stats sockets avoid a public admin endpoint. HAProxy installation includes optional socat command tooling.
- Use master-worker units, validated reloads and new-worker PID verification for compatible configuration changes. Unit/FD-limit changes use restart; disable/removal has a bounded graceful stop. No unconditional zero-downtime claim.
- Replace legacy bulk wipe with preview, strict generated-rule/unit recognition, backup, checked duplicate removal and refusal of unknown commands. Check Simple GRE script, unit, peer and known dependencies before removal. Retain source/backup on partial failure. Replace legacy raw script replay with read-only inspection.
- Stop implicit GRE TCP/conntrack/IPv6 tuning and automatic legacy conntrack sizing. Add explicit capacity/local-TCP profiles with a durable before/applied journal, apply recovery and restore that preserves administrator drift. Retire recognized historical persistence without guessed runtime defaults; untracked RPS/NOTRACK/shared firewall remain for review.
- Add AGENTS.md, dedicated HAProxy/tuning docs, mock failure/drift regressions and real reload/session, PROXY-wire and legacy cleanup namespace checks. Frozen gre-stable.sh is unchanged.

## v1.1.0 — Authenticated reverse connections and method selection

- Add an optional rathole 0.5.0 adapter, SHA-256-pinned x86_64 GNU/Linux / aarch64 musl installer, Noise NK server authentication, TCP/UDP/both service presets, scoped systemd creation/removal and failed-start cleanup. Existing names and unsupported binaries are retained. Private keys/tokens stay in restricted configs.
- Add a reverse-engine chooser and offline `--catalog` with implemented capabilities, tradeoffs and explicitly unimplemented methods. Add English/Finglish/Farsi reverse setup guidance.
- Check new FRP/rathole entrance listeners against assigned IPs, sockets and known managed/legacy forwards under the shared lock; include rathole services in doctor.
- Fail closed on unreadable/nonregular/dangling state and explicit missing state files. Only an absent default state means a new installation.
- Clamp owned original-direction nftables TCP SYN MSS using the route MSS. Real GRE packet captures verify MSS 1390 at MTU 1430 and preservation of an advertised 1200 MSS.
- Add rathole TOML, validation, version-report, name-preservation, port-reservation and failed-start regression tests; verify actual TCP/UDP transfer and reject a wrong Noise public key in isolated namespaces.
- Record source-backed backend recommendations and remaining architectural/operational gaps. No Kariz code/protocol/configuration is copied or integrated.

## v1.0.2 — Safer edits and configuration inspection

- Preserve disabled state and source-IP policy while editing; reject stale concurrent edits instead of overwriting another session.
- Compare equivalent IPv6 forms, reject duplicate endpoints/direct self-loops and unsupported HAProxy strategies, and account for relay socket conflicts across interfaces.
- Local listener checks distinguish specific bind addresses instead of blocking an unrelated same-port service on another IP; wildcard sockets remain conservative conflicts.
- Preflight enabled local addresses, selected kernel interfaces, IPv6 forwarding and generated iptables/nftables/HAProxy rules before replacing state or restarting services. Realm receives schema/render validation; no separate native config verifier is claimed.
- Add read-only `--validate`, `--plan`, `--state-file` and `--doctor`, menu config previews, and restore previews.
- Block GRE deletion while managed records reference its interface or default internal address range, including disabled records. Manual/legacy/custom-route dependencies still require operator inspection.
- Replace rollback state atomically and attempt both kernel and relay recovery even if one fails.
- Derive release header and legacy logo from the single manager version constant. Add regression and isolated preflight/traffic checks; update operation and architecture docs.
- Exercise real keyed GRE encapsulation at MTU 1430 with 128 KiB TCP and 1200-byte UDP payloads in private namespaces.

## v1.0.1 — Modular traffic manager

Starts the MAJOR.MINOR.PATCH manager version line; historical v13.x numbers remain unchanged. State schema versions and backend component versions are independent.

- Modular Bash source and deterministic standalone build; frozen stable script unchanged.
- Task-based default UI, dark/light/plain themes, four accents, English/Finglish/Farsi guide selection and Persian readability check; no-root demo/preview.
- Preserved legacy menu numbers 1–14, modern entry 15 and CLI --legacy.
- Validated v1 connection records, flock serialization, grouped create/edit/delete/enable/disable, restore points and best-effort rollback.
- Owned-chain iptables and native nftables TCP/UDP forwarding, IPv4/IPv6 config, explicit bind and weighted random destination selection.
- Optional Realm and HAProxy per-connection services, multi-destination strategies and checked HAProxy TCP failover.
- Optional FRP reverse TCP/UDP, TCP stream mux, WS, WSS and QUIC. WSS has an HAProxy TLS gateway with loopback-only frps and explicit client CA.
- SHA-256-pinned Realm 2.9.6 / FRP 0.71.1 installers for amd64/arm64.
- Legacy grouped rule deletion drains duplicates and preserves shared/unknown rules. Bounded numeric validation; safer GRE failure cleanup, watchdog start dependency and shortcut update; repeated Realm deletion preserves the next endpoint header.
- CI, pure-logic/config tests and isolated Linux network-namespace tests with real TCP/UDP traffic and optional relay engine probes.
- Documentation corrects unsupported capacity claims and the multiple-entrance-port NAT workaround. No universal throughput/latency or full rollout guarantee.

## v13.9 (2026-07) — Turbo

- NEW menu 14 (Performance): High-Load profile in two tiers (524k / 1048k conntrack), RPS spreading across cores, GRE NOTRACK, status screen (conntrack %, RPS state, per-tunnel RX/TX from /proc), in-script scaling guide. Kernel-side only — zero new processes.
- NEW optional per-tunnel MTU prompt (Enter = 1430 compat default; max 1472 v4 / 1452 v6).
- Dashboard shows Turbo (profile) state; new tunnels auto-inherit RPS when profile active.

## v13.8 — Bugfix wave

- MSS clamp-to-pmtu + RELATED,ESTABLISHED FORWARD accept + GRE INPUT via new shared `gre-firewall.service` (boot-persistent; fixes ufw/docker FORWARD DROP and PMTUD stalls).
- Critical: numeric validation of menu indexes (garbage input used to select/delete entry 0).
- Watchdog `PartOf=` tunnel unit (manual stop no longer resurrected).
- Per-rule FORWARD accepts for menus 7/9; Simple GRE now opens firewall at all.
- edit_advanced_rules de-dups (deletes old live rules before replaying file); eval removed everywhere.
- install_deps package mapping (ip→iproute2, awk→gawk, drop unused bc); non-apt warning.
- Negative IP-detection cache (10 min) kills 6 s menu lag on v6-less hosts.
- Tunnel counter counts ip6gre, excludes gre0; overwrite check by unit file; both iface names removed on overwrite; safer shortcut download (temp file); base sysctl always rewritten + 16 MB TCP buffers; conntrack base 262144 with first forwarding rule; SSH hijack warning (ss) in menu 9; realm unit logs to journal; `read -r` everywhere.

## v13.7 — Hardened

- Keyed tunnels (`key $TID`) — multiple tunnels per server pair; wire-incompatible with v13.6.
- Watchdog actually restarts on 3 lost pings (was a no-op ping loop in v13.6).
- Octet-checked validate_ipv4, validate_port, TID clamped 1-250; eval removed from menu 9 input path; caches moved /tmp → /run/gre-manager (0700); ip6tables GRE accept; correct `ufw allow proto gre from any to any` syntax.

## v13.6 — FROZEN (gre-stable.sh)

- Legacy baseline. Unkeyed tunnels, passive keepalive, TID up to 65000. Kept only for existing installs; REPO_URL points to itself. Never edit.
