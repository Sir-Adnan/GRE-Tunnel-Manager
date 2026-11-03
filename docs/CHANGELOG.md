# Changelog

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
