# CLAUDE.md

## Project

`gre.sh` — interactive Bash TUI (root, Debian/Ubuntu + systemd) that builds GRE/ip6gre tunnels between Iran and foreign VPSes, manages iptables port forwarding, a Realm (Rust) relay, and an opt-in kernel-side High-Load profile for 10k-100k+ concurrent users. UI strings are English; README.md is Persian (user-facing/marketing). Detailed dev docs live in `docs/` — read them on demand instead of re-deriving from source:

- `docs/ARCHITECTURE.md` — section map, function inventory, addressing/naming scheme
- `docs/ARTIFACTS.md` — every file/service/iptables rule created on target servers
- `docs/DEVELOPMENT.md` — workflow, testing, release checklist, known pitfalls
- `docs/PERFORMANCE.md` — High-Load design, sizing math, non-goals
- `docs/CHANGELOG.md` — version history

## Files

| File | Status |
| --- | --- |
| `gre.sh` | The ONLY actively developed file (current: v13.9) |
| `gre-stable.sh` | FROZEN legacy v13.6. Never edit, never "fix", never delete |
| `README.md` | Persian, customer-facing. Update when features change |
| `CLAUDE.md`, `docs/` | English, dev-facing |

## Hard rules

1. **Zero-footprint**: the manager must add NO daemons, timers, cron jobs, or background processes. All tuning is kernel-side (sysctl, iptables, /sys). Only allowed persistent processes: the per-tunnel watchdog bash loops (~2 MB each). New features that would need a resident process must be rejected or made read-on-demand.
2. **Wire compatibility**: tunnels use `key $TID`; inner addressing is `10.0.TID.0/30` + `fd00:TID::/64`; MTU default 1430; TID range 1-250. Never change these defaults — they must match peers built by older v13.7+ installs. New knobs must default to the old behavior (see the MTU prompt: Enter = 1430).
3. `gre-stable.sh` stays untouched (its REPO_URL intentionally points to gre-stable.sh).
4. Menu numbers 1-14 are a UX contract — never renumber, only append.
5. **Bash safety**:
   - every `read` uses `-r`;
   - validate menu indexes with `^[0-9]+$` BEFORE any array lookup (unvalidated subscripts arithmetic-evaluate to 0 → selects/deletes first item);
   - never `eval` user or file content — stored iptables rules are executed via plain word-splitting (`$cmd 2>/dev/null`);
   - awk must be mawk-safe: no `{n,m}` regex intervals (use `[0-9]?[0-9]?`);
   - `%` only in printf, never `%%` in echo;
   - heredocs: quote the delimiter (`<<'EOF'`) for static generated scripts, unquoted only when expansion is intended.
6. **Line endings**: repo stores LF; Windows worktree may show CRLF. Never introduce CRLF into committed content. Test with `tr -d '\r' < gre.sh | bash -n` (plain `bash -n` on the worktree file can false-fail).

## Versioning

Bump the version in BOTH spots: header comment block AND `draw_logo()`. Add a `docs/CHANGELOG.md` entry and update README's version table.

## Testing (no CI yet)

- Syntax: `tr -d '\r' < gre.sh > /tmp/t.sh && bash -n /tmp/t.sh`
- Also `bash -n` every embedded generated script (extract heredoc bodies).
- Pure-bash logic (validators, regex, math) is testable locally in bash.
- systemd/iptables/GRE behavior needs a real Debian VPS pair — checklist in `docs/DEVELOPMENT.md`.

## Layout of gre.sh (top to bottom)

CONSTANTS → root check → UTILITIES (install_deps, setup_shortcut, get_bind_ip, fix_firewall, validators, detect_local_ips, get_active_tunnels) → UI (draw_logo, draw_dashboard, print_guide_box) → CORE GRE (apply_sysctl, setup_tunnel, remove_tunnel, edit_tunnel) → SIMPLE GRE (menu 7/8) → ADVANCED FORWARDING (menu 9-11, FW_SCRIPT) → WIPE (menu 12) → PERFORMANCE module (menu 14, perf_*) → REALM module (menu 13, realm_*) → MAIN LOOP (menu + case).
