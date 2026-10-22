# Architecture — v1.2.1

Modular Bash source is concatenated by `tools/build.py` into standalone `gre.sh`. Runtime does not download/source modules. Sourcing the release defines functions/constants only; execution is guarded by `BASH_SOURCE[0] == $0`.

| Module | Responsibility |
| --- | --- |
| core | Bounded validators, endpoints, paths, privileges, flock |
| ui | Responsive terminal panels, palettes, Guided/Compact preferences, English/Finglish/Farsi help |
| haproxy | Validated TCP options, rendering, local stats, worker readiness and settings UI |
| state | TSV records, conflicts, snapshots, apply/recovery |
| firewall | Owned iptables chains and native nftables table |
| relays | Optional component installation and Realm/HAProxy services |
| transports | FRP, transports and WSS TLS gateway |
| rathole | Pinned optional installer, Noise NK reverse connections, scoped services/removal |
| catalog | Offline capability guide and reverse-engine selection |
| inspect | Offline previews/validation, preflight, host health report, GRE dependencies |
| tuning | Explicit global sysctl profiles, before/applied journal, drift-aware restore |
| cleanup | Closed legacy inventory, backed-up scoped deletion and historical retirement |
| menus | Task menus, grouped CRUD, diagnostics, legacy cleanup |
| legacy | Compatible GRE, Simple GRE, performance and old utilities |

## Navigation

The main menu has seven named sections: GRE Tunnel, Port Forwarding, HAProxy Tunnel, Realm Tunnel, Reverse Tunnel, Load Balancing and Settings & Tools. GRE has direct Kharej/Iran choices; these roles retain the original wire contract regardless of geography. Legacy numbers 1–14 remain in Settings & Tools → Old menu and `--legacy`.

Engine menus use a dynamically scoped `GTM_ENGINE_FILTER` only in `gtm_records` presentation/selection. After selecting stable IDs, mutations reload the **entire** state under the lock and preserve other engines. Never pass a filtered presentation array directly to reconciliation. Guided shows short option descriptions; Compact hides them. Preferences remain data, including the optional layout key; older preference files still load.

## State

Version-1 records have 12 nonempty tab-separated fields:

`id, name, engine, protocol, bind, port, strategy, enabled, snat, interface, targets, schema_version`

HAProxy advanced settings use version 2 with a 13th options field. The first 12 fields retain their order, with `schema_version=2`. Options are closed, bounded semicolon-separated key/value data; old records load baseline defaults. Edits, enable/disable and snapshots preserve the field. Old manager releases cannot load v2 records; downgrade needs an appropriate v1 snapshot. See [HAPROXY.md](HAPROXY.md).

Only an absent default state is treated as a new installation. Explicit missing files, directories, dangling links and unreadable state fail closed; they must not reconcile as an empty configuration. CLI state inspection requires regular files, not streams.

Targets: comma-separated `IPv4:port@weight` or `[IPv6]:port@weight`. IDs: F plus six digits. Names: bounded ASCII. All fields are validated before rendering. Kernel target address families must match bind; relays can mix families. Canonical comparison keys make equivalent IPv6 spellings identical for listener conflicts, duplicate targets and direct self-loops; record spelling itself is preserved. Only kernel listeners can be separated by explicit entrance interfaces; relay sockets cannot. Files are never sourced/evaluated. Preferences have a closed-key TSV parser.

Mutations acquire flock, reload state, validate a candidate and preflight it before snapshotting and replacing the data file. Edits compare the current row against the exact row originally opened; a concurrent change requires reopening the editor. Preflight checks assigned addresses, existing entrance interfaces, IPv6 forwarding and native syntax checks for iptables/nftables/HAProxy without applying rules. Realm has schema/render validation only. Failure after state replacement atomically restores the previous state and attempts both kernel and relay reconciliation; recovery failure is reported. There is no globally atomic transaction across multiple kernel tables and systemd. Native nftables uses one batch; iptables uses per-table restore batches. Optional package installation occurs earlier and is not rolled back by this transaction.

`--validate` and `--plan` use readable state files without root or temporary files. Plans render desired enabled configs without probing destinations; they exclude old-resource cleanup and separate FRP instances. `--doctor` reads host status without active probes or mutation and returns nonzero for invalid saved state; unavailable optional tools are informational.

Legacy rules keep their ownership. Strict generated DNAT syntax is grouped for deletion. Duplicates are drained; shared SNAT/FORWARD lines and unknown manual lines are preserved when needed. Old listeners must not overlap new ones.

## Runtime

- No resident manager, polling service, timer or cron.
- Kernel forwarding uses a oneshot boot reconciler. Root-owned serialized Bash functions form its standalone runner, supporting process-substitution startup.
- Realm/HAProxy: one service per enabled connection. Unchanged running config and unit are retained. HAProxy configuration-only changes use a master-worker reload when the unit and previous worker socket are compatible; readiness requires a new worker PID. Unit/FD budget changes or missing old readiness require restart. Local stats use mode-600 Unix sockets; socat is an explicit HAProxy command dependency, not a daemon. No HTTP admin endpoint is exposed.
- FRP: separate entrance/destination services. TCP destinations can share a group/public port.
- WSS: HAProxy terminates TLS; frps binds loopback, without a second inner TLS requirement. frpc verifies the selected CA. Gateway lifecycle is tied to its FRP entrance.
- rathole: one local entrance/destination service per instance, TCP/UDP/both service ports with authenticated Noise NK over TCP. The entrance generates a private key; the destination pins its public key. Tokens/private keys are in mode-600 config files, never command arguments. New names cannot overwrite existing instances. Startup failure stops/removes the new owned instance; stop failure keeps files and reports recovery needs. This is separate from TSV restore points, like FRP.
- Reverse entrance listeners check assigned IPs, current sockets and known legacy/managed forwards under the shared lock. Unrecognized manual NAT rules and inactive reverse instances are not fully modeled; runtime startup and operator firewall inspection remain necessary.
- Native nftables clamps existing TCP SYN MSS for owned original-direction DNAT flows using route MSS at forward priority -150. Linux's MSS option setter never increases a smaller advertised value. This is route-based clamping, not active path-MTU discovery.
- Kernel distribution is weighted-random per new conntrack flow, with no health checks. HAProxy provides checked TCP failover; Realm presets do not claim checked failover.

## Compatibility

Modern navigation is default. `--legacy` preserves numbers 1–14; 15 returns to modern. GRE keys, addressing, interface/unit names, IDs 1–250 and MTU 1430 remain compatible with v13.7+. Side A maps to old kharej, Side B to iran, irrespective of geography. `gre-stable.sh` remains frozen v13.6. GRE deletion is guarded by managed-record references to its interface or default internal address range (including disabled records). Unknown manual/legacy rules and custom routes are outside that guard; no forwards are automatically deleted.

Legacy 10 is now read-only script inspection, 12 is scoped cleanup, and 14 is explicit journaled tuning. Bulk removal refuses unknown commands/custom units. No saved shell line is executed by cleanup. New GRE setup no longer writes global TCP/conntrack/IPv6 tuning. Historical files can be retired only when recognized, with unknown runtime values preserved. New tuning uses an independent before/applied journal and conditional restore; see [TUNING-CLEANUP.md](TUNING-CLEANUP.md).
