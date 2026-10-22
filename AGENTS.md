# Agent instructions

This repository is a modular Bash control plane for Linux server links and traffic forwarding. Keep packet processing in the kernel or selected upstream engine. No mandatory resident manager, polling agent, timer or cron.

## Before changes

- Read `CLAUDE.md`, `docs/ARCHITECTURE.md`, `docs/ARTIFACTS.md`, `docs/DEVELOPMENT.md` and `docs/PERFORMANCE.md` when changing those contracts.
- Edit `src/*.sh`, then regenerate `gre.sh` with `python3 tools/build.py`. Never hand-edit the generated release.
- `gre-stable.sh` is frozen v13.6. Keep its bytes unchanged.
- Preserve GRE keys, IDs 1–250, addresses, interface/unit names, MTU 1430 and legacy menu numbers 1–14.

## Implementation

- Treat configuration as validated data. Never source user data or use eval. Use arrays, `read -r`, bounded decimal validation and checked results.
- Keep mutations under flock; reload state after locking, reject stale edits, snapshot before apply and report rollback failure.
- Change only resources whose ownership is established. Preserve unknown/manual firewall rules and files; never flush the host firewall or conntrack.
- Make global tuning explicit. Record prior values before a write and restore only values still matching what this manager applied. Never guess administrator defaults.
- Keep HAProxy TCP forwarding distinct from UDP services, TLS termination and TLS passthrough. PROXY protocol is opt-in and requires a compatible destination.
- Use ASCII technical labels. Help may be English, Finglish or opt-in Farsi; never reverse or reshape technical values.
- Keep user-facing names familiar: GRE Tunnel, Port Forwarding, HAProxy and Realm. Keep the main menu short; put add/show/edit/delete inside each section. Engine filters are presentation-only: reload the complete state under lock before any mutation so other engines are preserved.
- Keep Bash as the only runtime language dependency. Python is for build/tests only; optional command-line dependencies must be documented.
- Keep LF endings, update affected docs and changelog, and use semantic release versions independently of state schema versions.
- Do not promise universal throughput, capacity, CPU/RAM, zero downtime or latency improvements.

## Verification

- `python3 tools/build.py --check`
- `python3 -m unittest discover -s tests -v`
- ShellCheck all modern source modules at warning level, excluding SC2034 for cross-module globals; see CI for the current module list.
- `sudo bash tests/linux_namespace.sh` for networking changes. Use private namespaces, not host firewall rules.
- `git diff --check` and verify `gre-stable.sh` is unchanged.
- Separate local validation from real two-VPS reboot/systemd/UFW/Docker/MTU/load readiness in reports.

Commit/push only when the user authorizes it. Never include `.work`, downloaded binaries, secrets or local test artifacts. Do not copy or wrap Kariz code/protocol/configuration under its current restrictive license.
