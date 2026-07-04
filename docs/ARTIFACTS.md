# Server Artifacts

Everything `gre.sh` creates on a target server. Use this to reason about state, cleanup, and reboot behavior without re-reading the script.

## Files & services

| Path | Created by | Purpose | Removed by |
| --- | --- | --- | --- |
| `/etc/systemd/system/gre-tun-$TID.service` | setup_tunnel (menu 1/2) | builds tunnel device at boot (oneshot, RemainAfterExit) | remove_tunnel (menu 3), overwrite on re-create |
| `/etc/systemd/system/gre-keepalive-$TID.service` | setup_tunnel | watchdog loop (PartOf gre-tun-$TID) | remove_tunnel |
| `/etc/sysctl.d/99-gre-tuning.conf` | apply_sysctl (every tunnel create; always rewritten) | ip_forward, BBR+fq, 16 MB TCP buffers | manual only |
| `/usr/local/bin/gre_firewall.sh` | fix_firewall (rewritten every call) | idempotent shared rules: GRE INPUT, MSS clamp, ESTABLISHED accept (v4+v6) | manual only |
| `/etc/systemd/system/gre-firewall.service` | fix_firewall (first call) | replays gre_firewall.sh at boot | manual only |
| `/opt/simple_gre_script.sh` | setup_simple_gre (menu 7) | tunnel + DNAT lines for Simple mode (single instance, overwritten per run) | remove_simple_gre (8), wipe (12) |
| `/etc/systemd/system/simple-gre.service` | setup_simple_gre | replays the above at boot | remove_simple_gre, wipe |
| `/usr/local/bin/gre_custom_rules.sh` (FW_SCRIPT) | ensure_forward_service (menu 9) | literal iptables lines + `nf_conntrack_max=262144` sysctl line | delete_advanced_rules (11, when emptied), wipe (12) |
| `/etc/systemd/system/gre-custom-rules.service` | ensure_forward_service | replays FW_SCRIPT at boot | same as above |
| `/etc/sysctl.d/98-gre-highload.conf` | perf_apply_profile (menu 14) | High-Load sysctls (conntrack sizing, ports, backlogs) | perf_remove_profile |
| `/etc/modules-load.d/gre-conntrack.conf` | perf_apply_profile | loads nf_conntrack before systemd-sysctl at boot | perf_remove_profile |
| `/usr/local/bin/gre_perf.sh` | perf_install_tools | RPS masks + GRE NOTRACK (idempotent; `boot` arg sleeps 5 s) | perf_remove_profile |
| `/etc/systemd/system/gre-perf.service` | perf_install_tools | runs gre_perf.sh at boot (Type=simple, non-blocking) | perf_remove_profile |
| `/etc/realm/config.toml` (+ `.bak`) | realm menu (13) | realm endpoints (TOML) | realm uninstall |
| `/etc/systemd/system/realm.service` | realm menu | realm daemon (Restart=always, journal logging) | realm uninstall |
| `/usr/local/bin/realm` | realm menu | realm binary (GitHub latest, arch x86_64/aarch64) | realm uninstall |
| `/usr/local/bin/igre` | setup_shortcut | self-download of gre.sh from REPO_URL | menu 5 re-installs |
| `/run/gre-manager/{v4,v6}.cache` | detect_local_ips | public IP cache, 60 min TTL | menu 6, reboot (tmpfs) |
| `/run/gre-manager/{v4,v6}.miss` | detect_local_ips | negative cache, 10 min TTL | menu 6, reboot |

## Runtime iptables/ip6tables rules

| Table/Chain | Rule | Source | Persisted via |
| --- | --- | --- | --- |
| filter INPUT | `-p gre -j ACCEPT` | gre_firewall.sh | gre-firewall.service |
| mangle FORWARD | `-p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu` | gre_firewall.sh | gre-firewall.service |
| filter FORWARD | `-m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT` (inserted) | gre_firewall.sh | gre-firewall.service |
| nat PREROUTING | `-p tcp/udp --dport L -j DNAT --to-destination D:P` | menu 7 / menu 9 | simple-gre / gre-custom-rules |
| nat POSTROUTING | `-o gre_simp -j MASQUERADE` (7) / `-d D -p X --dport P -j MASQUERADE` (9) | menu 7 / 9 | same |
| filter FORWARD | `-d D -p tcp/udp --dport P -j ACCEPT` (inserted) | menu 7 / 9 | same |
| raw PREROUTING+OUTPUT | `-p gre -j NOTRACK` | gre_perf.sh | gre-perf.service |
| ufw | `ufw allow proto gre from any to any` | fix_firewall | ufw itself |

## Reboot behavior

Everything above self-restores: units are `WantedBy=multi-user.target`; sysctl drop-ins apply via systemd-sysctl (nf_conntrack pre-loaded via modules-load.d); `/run` caches vanish (harmless, re-probed).

Cleanup gaps (accepted, documented): `99-gre-tuning.conf`, gre-firewall unit/script, and ufw's gre allow survive full tunnel removal — harmless idempotent allows/tuning. DNAT rules referencing a deleted tunnel are NOT auto-removed (menu 3 prints a reminder; remove via menu 11).
