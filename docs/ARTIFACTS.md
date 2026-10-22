# Server Artifacts

## v1 managed resources

| Path | Owner / lifecycle |
| --- | --- |
| `/etc/gre-manager/connections.tsv` | Validated v1/v2 connection records; atomic replacement |
| `/etc/gre-manager/preferences.tsv` | Historical appearance preferences; ignored by v1.2.2+, retained if already present |
| `/etc/gre-manager/manager.lock` | Exclusive mutation lock |
| `/etc/gre-manager/id-counter` | Monotonic connection ID allocation, retained across deletion/restore |
| `/etc/gre-manager/backups/*.tsv` | Forwarding restore points; sensitive topology data |
| `/etc/gre-manager/backups/legacy-*.sh` | Raw backup before legacy group deletion; executable root data, not a modern restore point |
| `/etc/gre-manager/generated/F*.conf` | Per-connection Realm/HAProxy config |
| `/run/gre-manager/haproxy/F*.sock` | HAProxy read-only Unix stats sockets, mode 600 inside mode-700 directory |
| `/etc/gre-manager/tuning.tsv` | Validated before/applied sysctl journal; independent of forwarding snapshots |
| `/etc/sysctl.d/99-z-gre-manager-owned.conf` | Explicit managed global tuning; conditional restore/release |
| `/etc/gre-manager/backups/{cleanup,tuning,retired-tuning}-*/` | Private pre-operation artifacts for scoped deletion, tuning recovery or historical retirement |
| `/etc/systemd/system/gtm-F*.service` | Opt-in per-connection relay service; removed when disabled/deleted |
| `/usr/local/lib/gre-manager/apply.sh` | Generated self-contained boot reconciler; root-only executable |
| `/etc/systemd/system/gre-manager-forwarding.service` | Oneshot kernel reconcile, not a manager daemon |
| `/etc/gre-manager/gtm-frp-*.toml` | FRP entrance/destination config, including secret token |
| `/etc/systemd/system/gtm-frp-*.service` | Optional FRP services |
| `/etc/gre-manager/gtm-rathole-{entrance,destination}-NAME.toml` | Optional reverse config; secret token and entrance private key / destination public key |
| `/etc/systemd/system/gtm-rathole-{entrance,destination}-NAME.service` | Optional rathole services, removed only for the selected local instance |
| `/etc/gre-manager/gtm-gateway-*.conf` | WSS HAProxy gateway config; references operator-owned certificate |
| `/etc/systemd/system/gtm-gateway-*.service` | WSS TLS gateway tied to entrance lifecycle |
| `/usr/local/bin/{realm,frpc,frps,rathole}` | Optional pinned downloads, SHA-256 verified; retained after connection removal |

Config/state is root-owned with mode 600, containing directory 700. Temporary generation/download files use `/run/gre-manager` and private permissions. The manager does not delete operator certificates, unrelated services or optional binaries when deleting a connection. Backups are retained until the operator removes them.

Kernel resources: iptables `GTM_PRE`, `GTM_POST`, `GTM_FWD`, `GTM_MSS` and their parent jumps; nftables `table inet gre_manager` including per-target branch chains. Disabling/deleting the final record empties owned chains/table rather than flushing host rules. Existing conntrack flows may live until their normal expiration; the manager does not flush the host conntrack table.

The nftables table also owns a forward-hook MSS chain at priority -150, scoped to original-direction managed TCP DNAT flows. FRP/rathole secrets are outside TSV snapshots and need a separate restricted backup. Their local deletion does not contact or delete the peer on another server.

IPv4 forwarding is enabled when required and re-enabled by the boot runner. IPv6 forwarding must be deliberately configured by the operator, including RA behavior where relevant. Global forwarding settings are not automatically reverted on deletion.

## Legacy resources

The following inventory includes historical artifacts for migration. New GRE creation no longer writes the old tuning drop-ins or invokes the old performance helper. New legacy forwarding keeps required IPv4 forwarding but does not size conntrack or auto-enable IPv6 forwarding. Recognized historical tuning can be retired, without guessed runtime rollback; see [TUNING-CLEANUP.md](TUNING-CLEANUP.md).

## Files & services

| Path | Created by | Purpose | Removed by |
| --- | --- | --- | --- |
| `/etc/systemd/system/gre-tun-$TID.service` | setup_tunnel (menu 1/2) | builds tunnel device at boot (oneshot, RemainAfterExit) | remove_tunnel (menu 3), overwrite on re-create |
| `/etc/systemd/system/gre-keepalive-$TID.service` | setup_tunnel | watchdog loop (PartOf gre-tun-$TID) | remove_tunnel |
| `/etc/sysctl.d/99-gre-tuning.conf` | historical apply_sysctl; no longer created | old ip_forward, BBR+fq, 16 MB TCP buffers | recognized historical retirement; customized files kept |
| `/usr/local/bin/gre_firewall.sh` | fix_firewall (rewritten every call) | idempotent shared rules: GRE INPUT, MSS clamp, ESTABLISHED accept (v4+v6) | manual only |
| `/etc/systemd/system/gre-firewall.service` | fix_firewall (first call) | replays gre_firewall.sh at boot | manual only |
| `/opt/simple_gre_script.sh` | setup_simple_gre (menu 7) | tunnel + DNAT lines for Simple mode (single instance) | guarded scoped cleanup (8/12) |
| `/etc/systemd/system/simple-gre.service` | setup_simple_gre | replays the above at boot | remove_simple_gre, wipe |
| `/usr/local/bin/gre_custom_rules.sh` (FW_SCRIPT) | ensure_forward_service (menu 9) | literal generated iptables lines; old files can contain untracked sysctls | grouped deletion (11) / recognized bulk cleanup (12) |
| `/etc/systemd/system/gre-custom-rules.service` | ensure_forward_service | replays FW_SCRIPT at boot | same as above |
| `/etc/sysctl.d/98-gre-highload.conf` | historical performance profile | old unjournaled sizing, ports, timeouts, backlogs | recognized historical retirement |
| `/etc/modules-load.d/gre-conntrack.conf` | historical performance profile | old module-load persistence | recognized historical retirement |
| `/usr/local/bin/gre_perf.sh` | historical performance profile | old untracked RPS + GRE NOTRACK | fingerprint-checked retirement; runtime values retained |
| `/etc/systemd/system/gre-perf.service` | historical performance profile | old oneshot helper at boot | content-checked retirement |
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

Units and sysctl drop-ins are configured to restore at boot; verify real network readiness and host firewall ordering during rollout. `/run` caches vanish and are re-probed.

Shared gre-firewall unit/script and UFW's GRE allow remain outside the new journal and survive tunnel removal. Review these retained policies for the host's needs. Old tuning files need explicit historical retirement. Managed forwarding references block standard GRE/Simple GRE removal where recognized. Manual rules/custom routes and historical runtime RPS/NOTRACK still need operator inspection. New cleanup never calls an unscoped `systemctl reset-failed`.
