# Retiring old installations

Servers set up with the v13.x scripts can still carry their forwarding script, Simple GRE and tuning files. **Tools → Retire old installation** in the terminal removes the recognized ones; none of these actions flush the host firewall or the conntrack table. The old scripts themselves (`gre-stable.sh`, `legacy/`) and the old terminal menu were removed in v1.4.0; GRE tunnels they created (`gre-tun-N` units, IDs 1–250) keep working and are managed like new ones.

| Option | Removes |
| --- | --- |
| Remove all recognized v13.x forwards | Every generated DNAT/SNAT/FORWARD rule of `/usr/local/bin/gre_custom_rules.sh` and its unit |
| Remove one v13.x forward group | TCP and UDP rules of one entrance → destination pair; other lines stay |
| Remove Simple GRE | The Simple GRE script, unit and interface after dependency checks |
| Retire old tuning files | `99-gre-tuning.conf`, `98-gre-highload.conf`, the old module file and performance helper |

New forwards on an entrance port that an old script still forwards are refused until that rule is retired.

## Recognition and backups

Bulk forward removal requires a regular, non-symlink file with the known generator header. Only strict TCP/UDP DNAT commands and the generated target-matching SNAT/FORWARD commands are recognized; exact old forwarding/conntrack sysctl preambles are treated as historical persistence and never executed. Unknown commands, orphan target rules, malformed addresses/ports or a customized unit refuse the whole bulk operation before any change. Group removal keeps unknown lines.

Each action previews its resources, verifies firewall access, asks for confirmation and copies the source and unit to a private `backups/cleanup-TIMESTAMP-PID-RANDOM/` folder. A verified oneshot unit is stopped, matching duplicates are drained with checked `-C`/`-D` argument arrays and only the recognized persistence is removed after the rules are gone. If deletion fails partway, the source, unit and backup are kept and the partial result is reported; earlier live deletions are not rolled back. A saved script is executable root data: do not run an untrusted backup.

Simple GRE removal validates its generated script, unit, current interface peer and managed address/interface dependencies. References to `gre_simp` or `172.16.200.0/30`, including disabled records and recognized old DNAT rules, block removal.

Untagged old rules carry no ownership marker. Recognition relies on the saved generator file and strict syntax, not on telling an identical manual rule apart. Existing conntrack sessions can keep an old mapping after a rule is deleted.

## Old tuning files

Old installs did not record previous values. Retirement backs up the known drop-ins, module file and optional helper/unit, then removes their persistence. Drop-ins must contain only the known generated keys and values, the helper must match the known generator fingerprint and the unit its expected content; customized files or symlinks are kept.

No guessed defaults are written: runtime sysctls, RPS/RFS and untagged NOTRACK stay until a reboot or until the operator changes them. To bring tuning under management, apply groups on the [Optimization](OPTIMIZATION.md) page: the panel's drop-in sorts after the old files, and Reset there restores the values that were live when the panel first changed each key.
