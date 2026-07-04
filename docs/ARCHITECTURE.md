# Architecture

Single-file interactive Bash TUI (`gre.sh`). No libraries, no state files of its own — all persistent state lives in systemd units, generated shell scripts, and sysctl drop-ins on the target server (inventory: `ARTIFACTS.md`).

## Control flow

```
gre.sh (root)
 ├─ install_deps + setup_shortcut          (once, at start)
 └─ MAIN LOOP: draw_logo → draw_dashboard → menu → case
     ├─ 1/2  setup_tunnel kharej|iran      → writes 2 systemd units, starts them
     ├─ 3    remove_tunnel                 → stops/deletes units + interfaces
     ├─ 4    edit_tunnel                   → nano unit + restart
     ├─ 5    setup_shortcut (re-download)
     ├─ 6    clear IP caches
     ├─ 7/8  setup_simple_gre / remove_simple_gre
     ├─ 9-11 setup/edit/delete advanced forwarding (FW_SCRIPT)
     ├─ 12   wipe_all_gre_configs          (Simple + Forwarding only)
     ├─ 13   run_realm_menu (submenu loop)
     └─ 14   run_perf_menu  (submenu loop)
```

## Section map (order inside gre.sh)

| Section | Key functions | Notes |
| --- | --- | --- |
| CONSTANTS | — | paths for caches, firewall, perf, realm |
| UTILITIES | `install_deps`, `setup_shortcut`, `get_bind_ip`, `fix_firewall`, `validate_ipv4/6`, `validate_port`, `detect_local_ips`, `get_active_tunnels` | `fix_firewall` also writes the shared gre-firewall unit |
| UI | `draw_logo`, `draw_dashboard`, `print_guide_box` | dashboard reads caches, /proc, unit states — no probing when caches fresh |
| CORE GRE | `apply_sysctl`, `setup_tunnel`, `remove_tunnel`, `edit_tunnel` | per-tunnel unit pair: `gre-tun-$TID` + `gre-keepalive-$TID` |
| SIMPLE GRE | `setup_simple_gre`, `remove_simple_gre` | single instance, `/opt/simple_gre_script.sh` |
| ADV FORWARDING | `ensure_forward_service`, `setup_advanced_forwarding`, `edit_advanced_rules`, `delete_advanced_rules` | rules stored as literal iptables lines in FW_SCRIPT |
| WIPE | `wipe_all_gre_configs` | removes 7-11 artifacts, NOT standard tunnels |
| PERFORMANCE | `perf_install_tools`, `perf_apply_profile`, `perf_remove_profile`, `perf_show_status`, `perf_scaling_guide`, `run_perf_menu` | kernel-side only; see `PERFORMANCE.md` |
| REALM | `realm_*`, `run_realm_menu` | downloads realm binary from GitHub latest |
| MAIN LOOP | — | menu numbers are a UX contract |

## Naming & addressing scheme

| Item | Kharej side | Iran side |
| --- | --- | --- |
| Interface | `gre$TID` | `gre-out-$TID` |
| Inner IPv4 (/30) | `10.0.TID.1` (TID<256 ⇒ octet2=0) | `10.0.TID.2` |
| Inner IPv6 (/64) | `fd00:TID::1` | `fd00:TID::2` |
| Units | `gre-tun-$TID.service`, `gre-keepalive-$TID.service` | same names both sides |

- TID range 1-250 (also keeps `fd00:TID::` a valid hextet and excludes `gre0`).
- Tunnels carry `key $TID` → multiple tunnels per server pair; also why v13.7+ is wire-incompatible with frozen v13.6 (no key).
- Transport: IPv4 remote ⇒ `mode gre` (ttl 255); IPv6 remote ⇒ `mode ip6gre` (hoplimit 255). Local bind resolved via `ip route get $remote` (multi-home safe).
- MTU: per-tunnel prompt, default 1430 (compat), max 1472 (v4) / 1452 (v6) = 1500 − outer_hdr − 4(GRE) − 4(key).

## Key design decisions

- **systemd oneshot + RemainAfterExit** for tunnel units: ExecStart chain builds the device, ExecStop tears it down; failure of any ExecStart aborts the unit.
- **Watchdog** = bash loop unit (`Type=simple`, `Restart=always`): ping -c 3 -W 3 inner peer every 10 s; 3 lost pings ⇒ `systemctl restart gre-tun-$TID`; 15 s startup grace. `PartOf=gre-tun-$TID.service` so stopping/restarting the tunnel propagates to the watchdog (no resurrection of manually stopped tunnels).
- **Shared firewall unit** (`gre-firewall.service` → `gre_firewall.sh`): idempotent `-C || -A/-I` rules — GRE INPUT accept, TCPMSS clamp-to-pmtu (FORWARD/mangle), RELATED,ESTABLISHED accept (FORWARD) — both iptables and ip6tables. Written fresh on every `fix_firewall` call; needed because ufw/docker default FORWARD to DROP and plain runtime rules die on reboot.
- **Forwarding persistence**: FW_SCRIPT is a plain bash file of literal `iptables ...` lines replayed at boot by `gre-custom-rules.service`. Delete/edit paths convert `-A`/`-I` → `-D` (string replace, first occurrence) and execute WITHOUT eval. Edit flow snapshots old rules and deletes them live before re-running the file (prevents duplicate accumulation).
- **IP detection**: 3 HTTP APIs per family, 2 s timeout each, 60 min positive cache in `/run/gre-manager/` (root-owned tmpfs, mode 700) + 10 min negative cache (`*.miss`) so v6-less hosts don't lag the menu; instant local fallbacks (`hostname -I`, `ip -6 addr`).
- **Dashboard tunnel count** matches by interface NAME (`gre|gre-out-` + 1-250), not `type gre` — catches ip6gre, excludes kernel fallback `gre0`.
