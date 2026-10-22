# Legacy cleanup and explicit host tuning — v1.2.0

These are separate operations with separate backups. Removing a forward does not reset global host policy. Restoring global tuning does not remove a tunnel. None of the cleanup actions flush the host firewall or conntrack.

## Recognized legacy cleanup

**Legacy → 12** offers all recognized legacy forwards, Simple GRE removal and tuning management. Numbers remain compatible; the old destructive bulk implementation has been removed. **Legacy → 10** now inspects the saved script without editing/replaying arbitrary shell commands. Use modern connections for new configurations.

Bulk forward removal requires a regular nonsymlink file with the known generator header. Only strict TCP/UDP DNAT commands and the generated target-matching SNAT/FORWARD commands are recognized. Exact old forwarding/conntrack sysctl preambles are recognized as historical persistence, not executed. Unknown commands, orphan target rules, malformed addresses/ports or a customized unit refuse the whole bulk operation before mutation. Grouped deletion remains available to remove recognized groups while keeping unknown lines.

The manager previews resources, verifies firewall access, obtains confirmation and copies the source/unit to a private `backups/cleanup-TIMESTAMP-PID-RANDOM/` folder. It stops a verified oneshot unit, drains matching duplicates with checked `-C`/`-D` argument arrays, and removes only the recognized persistence resources after successful deletion. A check error is distinguished from a rule's absence. If deletion fails partway, it reports incomplete cleanup and retains source/unit and backup. Earlier live deletions are not globally rolled back; inspect the backup and remaining rules before retrying. The saved script is executable root data: do not automatically run an untrusted backup.

Simple GRE removal validates its generated script/known commands, unit, current local/remote interface peer and managed address/interface dependencies. References to `gre_simp` or `172.16.200.0/30`, including disabled modern records and recognized legacy DNAT, block removal. A mismatched interface peer is retained. Unknown manual routes and references remain outside the model and require review. Standard keyed GRE and modern forwarding/reverse resources are not selected by these cleanup actions.

Untagged legacy rules have no cryptographic ownership marker. Recognition relies on the saved generator file and strict syntax, not a claim that an identical manually added rule can be distinguished. Existing conntrack sessions can retain an old mapping after rule deletion. Service/host failures and interruptions still require operator recovery; this is not a multi-resource atomic transaction.

## Explicit journaled tuning

**Legacy → 14** now offers inspection, conntrack/queue capacity, a local TCP preset, tracked restore and historical retirement. Entering this submenu through the legacy flow holds the manager mutation lock; exit the submenu to let other manager operations proceed.

- GRE creation no longer rewrites BBR, TCP buffers, conntrack or IPv6 forwarding.
- New legacy forwarding no longer automatically sizes conntrack or enables IPv6 forwarding/RA. IPv4 forwarding is still enabled when IPv4 NAT requires it; IPv6 routing must be deliberately configured by the operator.
- The capacity preset selects 524288 or 1048576 conntrack entries plus queue/backlog settings. It does not infer user count or available RAM, modify hash buckets or shorten connection timeouts.
- The local TCP preset explicitly selects available BBR/fq and buffer bounds. An unavailable BBR fails before mutation. This affects locally terminated TCP, not the congestion control of transit endpoints. Existing sockets/qdiscs may not immediately adopt all changed defaults.
- New profiles do not write RPS/RFS sysfs values, add untagged GRE NOTRACK or install a performance helper process.

The journal `/etc/gre-manager/tuning.tsv` is validated data with `key<TAB>before<TAB>applied`. The previous value is captured before the first change, and remains the baseline across subsequent updates. A restricted set of sysctl keys is supported; malformed keys/values/duplicate entries refuse the operation. All values needed for the operation are read before writing anything. A changed administrator value or edited managed drop-in blocks reapplication.

After preview/confirmation, a private backup is created and the candidate journal is saved atomically **before the first runtime sysctl write**. Runtime changes are attempted and `/etc/sysctl.d/99-z-gre-manager-owned.conf` is replaced atomically after success. On failure, values still equal to that attempt's requested values are restored to their pre-attempt values; recovery failures retain the journal/backup and are reported. This is not atomic across multiple sysctls and files. Administrator/sysctl activity outside the manager lock can race it.

Restore compares each current value to its journaled applied value. Matching values return to the captured baseline; externally changed values are preserved and ownership released. Failed restorations retain only the entries needing retry and their persistence. An externally edited drop-in is retained for inspection rather than overwritten/deleted. Restore does not invoke `sysctl --system` or reset unrelated settings.

Conntrack limit writes also inspect the active flow count. A requested limit or saved baseline below current usage is refused; restore keeps that journal entry for a later retry. A missing/invalid usage counter also prevents this limit write. This guard does not reserve memory or remove the race with traffic arriving immediately afterward.

Backups live under `backups/tuning-*`; journals and drop-ins use mode 600 and a private config directory. They are separate from forwarding TSV restore points. Do not restore a topology snapshot expecting it to change host tuning. Other later sysctl drop-ins or administrator tools can override boot settings; verify reboot behavior on the target host.

## Historical tuning retirement

Old installs did not capture reliable before-values. Retirement previews and backs up the known `99-gre-tuning.conf`, `98-gre-highload.conf`, module-load file and optional old performance helper/unit, then removes their persistence. Drop-ins must contain only the known generated keys and values; the helper must match the known generator fingerprint and the unit its expected content. Customized files or symlinks refuse automatic retirement.

No guessed runtime defaults are written. Existing runtime sysctls, RPS/RFS and untagged NOTRACK remain because their previous values/ownership are unknown. Retirement prevents the recognized helper/drop-ins from reapplying; it cannot reconstruct a pre-install host state. Reboot behavior still depends on the kernel and other administrator files. Old shared GRE firewall rules and UFW allowance are retained and must be reviewed separately.

Retire old drop-ins before applying a new journaled profile to avoid conflicting persistence. The newly captured baseline is the value at migration time, which may already include old tuning; it is not an invented historical default. Private backups remain available for inspection/manual recovery.
