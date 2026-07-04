# Changelog

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
