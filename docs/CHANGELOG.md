# Changelog

## Unreleased — Phase 5A

- Add an engine/version capability matrix and cached fixed-command version probes; show adapter scope, native/schema validation and FRP client/server mismatches in the bilingual panel.
- Add bounded HAProxy plain HTTP GET readiness checks on a separate port, preserving TCP passthrough/defaults, with terminal/web controls and reachable-but-unhealthy namespace coverage.
- Fix the Go model dropping Realm version-3 option fields during record serialization; preserve them through round-trip create/edit.
- Add confirmed `panel-install.sh --uninstall` and a terminal removal action. Protect unresolved paired operations and Agent-shared resources; remove only panel files/counters and retain tunnels/forwarding.
- Keep application/package version 1.3.0 pending explicit approval of a future release. Do not overwrite published assets. Phase 5B–5D remain gated.

## Unreleased — Phase 4 leased two-node connections

- Add explicit `--operations` Agent opt-in while keeping the general local write API inaccessible remotely. Negotiate `connections.pair.v1` alongside protocol-1 inventory.
- Persist bounded Controller jobs and root receipts with preparation revisions, idempotent delivery, expiry, restart recovery, timed confirmation and fingerprint-guarded compensation. Expose individual and uncertain outcomes without claiming atomic multi-server changes.
- Coordinate GRE and FRP TCP/UDP creation on two selected Nodes, including the panel host or two remote servers. Keep engine installation, remote forwarding CRUD, Rathole key exchange and WSS outside this workflow.
- Add responsive bilingual setup/review, per-server progress and recovery controls. Preserve Nettinx and Vazirmatn. Poll active browser jobs only; retain the existing inventory cadence.
- Extend installer preservation, TLS/broker/Bash tests and real isolated GRE TCP/UDP checks. Document current-source packages; published v1.3.0 remains unchanged.

## Unreleased — Phase 3 read-only Nodes and Agents

- Add optional Controller enrollment and outbound inventory Agents without requiring a third server or an Agent on the panel host. Keep existing tunnel operations local.
- Define independent protocol 1, stable node IDs, closed capability negotiation, structured failures and separate metadata/inventory revisions. No remote operation endpoint is added.
- Pin the Controller authority before one-time enrollment, issue per-node mTLS identities, renew leaf certificates, preserve identities across updates and enforce revocation and certificate lifetime on every report/renewal, including reused TLS connections. Protect single-process state with file locks and atomic private writes.
- Add checksum/protocol-verified optional Controller/Agent installation, hidden invitation entry and a separately allowlisted read-only root broker. Browser HTTP never permits plaintext Agent transport.
- Add a lazy-loaded bilingual Nodes page, snapshot details, distinct connectivity/service status, collection timestamps, revocation confirmation and topology/recovery help. Preserve Nettinx colors and Vazirmatn.
- Bound enrollment, reports and retries; keep inventory memory-only with no history or queue. Document local-package installation because published v1.3.0 does not contain this source feature.

## Unreleased — Phase 2 installation and access

- Add modular quick/custom setup with automatic public-IP discovery, IP/domain addresses, IPv6 URL formatting, selected/random ports and generated credentials printed once.
- Add explicit HTTP alongside default HTTPS; align listener and cookie policy while retaining exact Origin/CSRF checks. Separate transport cookie names to avoid stale Secure-cookie conflicts. Explain HTTP transport on the bilingual login page and through accessible connection help.
- Accept user passwords with at least eight Unicode characters and at most 72 UTF-8 bytes; keep hidden confirmation and bcrypt hashing, and prohibit password arguments.
- Preserve existing configurations and certificates, default omitted protocols to HTTPS, validate incoming config before service stop, lock concurrent installs and reject version/checksum mismatches.
- Preserve default installation of the older published v1.3.0 package; reject unsupported new setup flags before stopping services. Support explicit local-package installation for the updated source. Preinstall engines only when requested.
- Require a matching release tag and remove asset clobbering from release automation. No new release or tag is published by these source changes.

## Unreleased — Phase 1 interface corrections

- Correct Radix state selectors for switches, checkboxes, tabs, overlays and orientation styling.
- Adopt shadcn sidebar navigation, top-bar appearance controls, action tooltips and hover/focus/tap help.
- Use Vazirmatn throughout the UI, localize display numbers and correct RTL alignment without reversing IP/port/code strings.
- Redesign traffic usage into full-width settings, per-connection counters and a lazily loaded Area chart based on bounded samples fetched during the page visit. Separate actual engine names from accounting methods; never aggregate overlapping GRE/forward totals.
- Expose optional forward/relay names in the main form and keep creation from dedicated HAProxy/Realm pages on that engine. Improve mobile form sizing and selection feedback.
- Move maintained documentation to English and add the phase-gated Node/Agent/installation/capability roadmap.
- This is an unreleased source change. HTTP installation was subsequently implemented in Phase 2 above; read-only Node/Agent inventory was subsequently implemented in Phase 3 above; remote mutations remain planned.

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
