# Retiring old installations

Servers set up with the v13.x scripts can still carry their forwarding script, Simple GRE and tuning files. The engine finds and removes the recognized ones; none of these actions flush the host firewall or the conntrack table. The old scripts themselves (`gre-stable.sh`, `legacy/`) were removed in v1.4.0 and the terminal menus in v1.6.0; GRE tunnels the old scripts created (`gre-tun-N` units, IDs 1–250) keep working and are managed like new ones.

First scan; it changes nothing:

```bash
sudo bash gre.sh --api legacy-scan
```

Each line is one item, tab-separated: `forwards STATE COMMANDS REASON`, `group TOOL PORT DESTINATION` (one per generated forward), `simple STATE LOCAL>REMOTE REASON` and `tuning STATE FILES REASON`. STATE is `ready`, `blocked` (REASON says why) or `absent`. Then retire one item:

| Command | Removes |
| --- | --- |
| `legacy-retire forwards` | Every generated DNAT/SNAT/FORWARD rule of `/usr/local/bin/gre_custom_rules.sh` and its unit |
| `legacy-retire group iptables 443 203.0.113.20:443` | TCP and UDP rules of one entrance → destination pair, as listed by the scan; other lines stay |
| `legacy-retire simple` | The Simple GRE script, unit and interface after dependency checks |
| `legacy-retire tuning` | `99-gre-tuning.conf`, `98-gre-highload.conf`, the old module file and performance helper |

Run each as `sudo bash gre.sh --api legacy-retire …` (on a panel server, `/usr/local/lib/gre-manager/manager.sh` works too). The command is the confirmation; scan first and read the result. New forwards on an entrance port that an old script still forwards are refused until that rule is retired.

## Recognition and backups

Bulk forward removal requires a regular, non-symlink file with the known generator header. Only strict TCP/UDP DNAT commands and the generated target-matching SNAT/FORWARD commands are recognized; exact old forwarding/conntrack sysctl preambles are treated as historical persistence and never executed. Unknown commands, orphan target rules, malformed addresses/ports or a customized unit refuse the whole bulk operation before any change. Group removal keeps unknown lines.

Each action verifies its resources and firewall access, then copies the source and unit to a private `backups/cleanup-TIMESTAMP-PID-RANDOM/` folder. A verified oneshot unit is stopped, matching duplicates are drained with checked `-C`/`-D` argument arrays and only the recognized persistence is removed after the rules are gone. If deletion fails partway, the source, unit and backup are kept and the partial result is reported; earlier live deletions are not rolled back. A saved script is executable root data: do not run an untrusted backup.

Simple GRE removal validates its generated script, unit, current interface peer and managed address/interface dependencies. References to `gre_simp` or `172.16.200.0/30`, including disabled records and recognized old DNAT rules, block removal.

Untagged old rules carry no ownership marker. Recognition relies on the saved generator file and strict syntax, not on telling an identical manual rule apart. Existing conntrack sessions can keep an old mapping after a rule is deleted.

## Old tuning files

Old installs did not record previous values. Retirement backs up the known drop-ins, module file and optional helper/unit, then removes their persistence. Drop-ins must contain only the known generated keys and values, the helper must match the known generator fingerprint and the unit its expected content; customized files or symlinks are kept.

No guessed defaults are written: runtime sysctls, RPS/RFS and untagged NOTRACK stay until a reboot or until the operator changes them. To bring tuning under management, apply groups on the [Optimization](OPTIMIZATION.md) page: the panel's drop-in sorts after the old files, and Reset there restores the values that were live when the panel first changed each key.
