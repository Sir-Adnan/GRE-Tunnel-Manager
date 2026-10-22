# Development Guide

## Golden rules

1. `gre-stable.sh` is FROZEN (v13.6, unkeyed tunnels). Never edit it. Its REPO_URL deliberately points to gre-stable.sh so its users never get silently upgraded into incompatibility.
2. **Zero-footprint rule**: no new daemons/timers/background processes, ever. Kernel-side tuning (sysctl, iptables, /sys) and read-on-demand screens only. Features that need a resident process go in as clearly-labeled opt-ins after explicit owner approval — default OFF.
3. **Compatibility contract** (both peers may run different script releases):
   - keyed tunnels (`key $TID`), inner `10.0.TID.0/30` + `fd00:TID::/64`, TID 1-250;
   - MTU default 1430 (prompt may allow higher, Enter must yield 1430);
   - unit names `gre-tun-$TID` / `gre-keepalive-$TID`, interfaces `gre$TID` / `gre-out-$TID`.
   Changing any of these breaks live deployments mid-upgrade.
4. Menu numbers are stable; append only (next free: 15).

## Bash conventions

- `read -r` always; pause prompts included.
- Numeric menu index? Validate `[[ "$idx" =~ ^[0-9]+$ ]]` BEFORE `${arr[$idx]}` — bash arithmetic-evaluates subscripts, so garbage input becomes index 0 (historically deleted the first tunnel).
- No `eval` on user/file content. Stored iptables lines are executed by plain word-splitting: `$cmd 2>/dev/null` (metachars stay literal args).
- Validators: `validate_ipv4` (octet-checked), `validate_ipv6` (route-based), `validate_port`. Use them; don't inline regexes.
- awk must run on mawk (Debian default): no `{n,m}` intervals — write `[1-9][0-9]?[0-9]?`.
- `%` literals: fine in `echo`, must be `%%` only inside `printf` format strings.
- Heredocs: `<<'EOF'` (quoted) for static generated scripts; unquoted `<<EOF` only when variable expansion is intended. Every generated script should end `exit 0` if intermediate commands may legitimately fail.
- Colors/UI: reuse the palette constants and `print_guide_box`; submenus follow the realm/perf pattern (clear + ascii title + numbered options + `read -r`).

## Testing

No CI yet (candidate: GitHub Action running shellcheck + bash -n).

Local (any OS with bash):

```bash
tr -d '\r' < gre.sh > /tmp/t.sh && bash -n /tmp/t.sh           # main syntax
# extract each generated-script heredoc and bash -n it too, e.g.:
sed -n "/cat <<'EOF' > \"\$GRE_FW_SCRIPT\"/,/^EOF$/p" /tmp/t.sh | sed '1d;$d' | bash -n
```

Real-server checklist (pair of Debian/Ubuntu VPSes):

1. Create tunnel both sides (same TID) → `ping 10.0.TID.<peer>` works.
2. `systemctl stop gre-tun-$TID` → watchdog must NOT resurrect it; `start` restores.
3. Reboot one side → tunnel, forwarding, firewall rules all return.
4. On a ufw-enabled Iran box: menu 9 forward → client connect through it works.
5. Menu 14 profile: `cat /proc/sys/net/netfilter/nf_conntrack_max` shows tier value; `cat /sys/class/net/gre*/queues/rx-0/rps_cpus` non-zero on multi-core.
6. Delete flows (3, 8, 11, 12) leave no dangling units: `systemctl list-units 'gre-*'`.

## Release checklist

1. Bump version in BOTH: header comment + `draw_logo()`.
2. `bash -n` (via `tr -d '\r'`) + heredoc extraction checks.
3. Update `docs/CHANGELOG.md`; update README (Persian) if user-visible.
4. Commit; keep gre-stable.sh untouched in the diff.

## Known pitfalls (learned the hard way)

| Pitfall | Detail |
| --- | --- |
| Array subscript injection | unvalidated `read idx` + `${arr[$idx]}` → index 0 selected; worst case arbitrary arithmetic evaluation |
| CRLF | Windows worktree shows CRLF; repo is LF. `bash -n` directly on worktree can false-fail; committed content must stay LF |
| `list-units` for existence | misses unloaded units — check the unit FILE path instead |
| `type gre` link filter | ip6gre is a different netlink type; kernel fallback `gre0` also exists — match interfaces by name |
| ufw/docker FORWARD DROP | DNAT silently dies without explicit FORWARD accepts + ESTABLISHED rule |
| conntrack sysctls at boot | `net.netfilter.*` keys fail unless nf_conntrack is loaded first → modules-load.d file |
| apt package names | tool `ip` ⇒ package `iproute2`; `awk` ⇒ `gawk` |
| Replaying `-A` rule files | re-running an append-only rules file duplicates rules — delete old live rules first (see edit_advanced_rules) |
| MASQUERADE ceiling | ~64k concurrent per (dest IP, dest port); document multi-port workaround, don't "fix" silently |
