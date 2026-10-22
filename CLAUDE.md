# Project conventions

GRE / Traffic Manager v1 is a modular Bash TUI for server links, kernel forwarding, optional relays and reverse connections. Technical labels stay ASCII; guides support English, Finglish and native Farsi with a terminal readability test.

Cross-agent instructions are in `AGENTS.md`. Keep both references consistent; `docs/HAPROXY.md` and `docs/TUNING-CLEANUP.md` describe the extended adapter/legacy contracts.

## Source of truth

Edit `src/*.sh`. Run `python3 tools/build.py` to regenerate standalone `gre.sh`. Never hand-edit generated output. `gre-stable.sh` is frozen v13.6: never edit/delete/upgrade it silently. Python is a build/test dependency only; runtime is Bash.

Read docs/ARCHITECTURE.md, docs/ARTIFACTS.md, docs/DEVELOPMENT.md and docs/PERFORMANCE.md before changing their contracts. README, docs/USER-GUIDE.md and docs/TERMINAL-UI.md are Persian; developer references are English. The HTML UX prototype is a design reference; the shipped interface runs inside SSH with numbered choices. Keep screenshots/previews faithful to the Bash release.

## Rules

1. No resident manager, timer, cron or metrics process. Kernel forwarding uses a oneshot boot runner. The user explicitly selects optional Realm/HAProxy/FRP/rathole services; WSS uses an additional HAProxy TLS gateway. Per-GRE watchdogs remain allowed.
2. Preserve v13.7+ GRE key, addressing, IDs 1–250, MTU 1430, interface names and unit names. Side A/B correspond to old kharej/iran roles irrespective of country.
3. Keep numbers 1–14 in the legacy menu. Modern navigation is separate; legacy 15 returns to it.
4. Configuration is data, never sourced/evaluated. Validate all fields before rendering. Use arrays for commands, read -r, printf, bounded decimal math and explicit result checks. Never use eval.
5. Change only owned firewall chains/table/services. Never flush the host ruleset or conntrack. Unknown/manual legacy lines stay. Repeated apply must not duplicate rules.
6. Use flock for mutations, reload state under lock, snapshot before apply and report recovery failure. Do not describe a multi-resource apply as globally atomic.
7. Native Persian is opt-in help only, in separate paragraphs from addresses/commands. Do not reverse strings or promise universal terminal shaping.
8. Preserve LF via .gitattributes. Build deterministically and update docs/changelog for behavior changes.
9. No universal user-count, CPU/RAM, speed or latency promises. Kernel distribution does not imply health checking. HAProxy adapter is TCP only. TCP Mux is FRP stream mux, not HTTP CONNECT tcpmux.

## Checks

- python3 tools/build.py --check
- python3 -m unittest discover -s tests -v
- shellcheck -s bash -S warning -e SC2034 src/{core,ui,haproxy,state,firewall,relays,transports,rathole,catalog,inspect,tuning,cleanup,menus}.sh
- sudo bash tests/linux_namespace.sh

Rollout additionally needs two-server reboot/systemd/UFW/Docker/MTU/certificate/real-load checks. Keep old and new listener tuples distinct until explicit migration. Bump GTM_VERSION in src/core.sh; the build header and legacy logo derive from it.
