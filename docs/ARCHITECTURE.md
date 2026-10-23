# Architecture — v1.3.0

Modular Bash source is concatenated by `tools/build.py` into standalone `gre.sh`. Runtime does not download/source modules. Sourcing the release defines functions/constants only; execution is guarded by `BASH_SOURCE[0] == $0`.

| Module | Responsibility |
| --- | --- |
| core | Bounded validators, endpoints, paths, privileges, flock |
| server_info | Session-cached host/address metadata and bounded optional public-IP/provider lookup |
| ui | Fixed ANSI styling, dedicated headers, numbered selectors and input rendering |
| haproxy | Validated TCP options, rendering, local stats, worker readiness and settings UI |
| realm_options | Validated Realm network options with compatible v3 records |
| state | TSV records, conflicts, snapshots, apply/recovery |
| firewall | Owned iptables chains and native nftables table |
| relays | Optional component installation and Realm/HAProxy services |
| transports | FRP, transports and WSS TLS gateway |
| rathole | Pinned optional installer, Noise NK reverse connections, scoped services/removal |
| catalog | Offline capability guide and reverse-engine selection |
| inspect | Offline previews/validation, preflight, host health report, GRE dependencies |
| forms | Read-only staged setup, port lists, remote endpoints, optional details and batch save |
| tuning | Explicit global sysctl profiles, before/applied journal, drift-aware restore |
| cleanup | Closed legacy inventory, backed-up scoped deletion and historical retirement |
| links / reverse_api / pair_api / api | Noninteractive owned-resource operations shared with the Go panel |
| panel | Optional panel lifecycle and engine preinstallation menus |
| menus | Task menus, grouped CRUD, diagnostics, legacy cleanup |
| legacy | Compatible GRE, Simple GRE, performance and old utilities |

## Navigation

The main menu has eight sections: GRE Tunnel, Port Forwarding, HAProxy Tunnel, Realm Tunnel, Reverse Tunnel, Load Balancing, Tools and optional Web Panel. GRE has direct Kharej/Iran choices; these roles retain the original wire contract regardless of geography. HAProxy and Realm have dedicated branded managers for setup, balancing, list/edit/delete, start/stop and status/logs. Legacy numbers 1–14 remain in Tools → Old Menu and `--legacy`.

Engine menus use a dynamically scoped `GTM_ENGINE_FILTER` only in `gtm_records` presentation/selection. After selecting stable IDs, mutations reload the **entire** state under the lock and preserve other engines. Never pass a filtered presentation array directly to reconciliation. Styling is fixed, English-only and foreground-only, respecting NO_COLOR/non-TTY/dumb output. Old preferences are ignored and no preference file is created. Theme/language/layout switches are removed.

Headers show the host/OS, full public/local addresses and network provider/ASN/country. A large ASCII GRE banner is used only at widths of at least 68 columns and heights of at least 34 rows; other windows keep a compact title. Interactive setup steps redraw the header so addresses remain available. Local identity is read without sourcing OS files or sending route probes. One optional HTTPS request to ipwho.is, with a two-second deadline and 8 KiB response limit, supplies the outgoing public address and approximate network attribution. Only validated addresses and sanitized ASCII scalar fields are displayed; metadata never sets a bind or target. It is cached in process memory, including lookup failure, until Tools → Refresh Server Info. `GTM_SERVER_LOOKUP=0` disables the external request. Sourcing, previews, demo, inspection commands and noninteractive output never perform that lookup. No cache file, timer or daemon is created.

Setup collects local ports, remote address and remote port, then shows review. Protocols, transport, balancing and PROXY/log options are numbered. Names are generated; optional details are off the main path. Relays default to an IPv4 wildcard listener; kernel rules require a concrete local address, suggested by a route lookup without transmitting packets. Wildcard relay preflight rejects a target matching a local address on its own listening port.

One setup accepts up to 32 unique local ports, including bounded ranges. Each port becomes an independent existing-schema record and ID. The user chooses fixed destination port(s) or matching local/remote ports. The full batch is rendered/validated, then appended to freshly loaded full state under one lock, with one counter update and one commit/preflight/snapshot/apply. Editing remains single-record and preserves the old options/state/source policy. Service install is after review and outside rollback, as before.

## State

Engine adapter/version profiles live in `panel/internal/model/engines.go`, independently of Node transport capabilities. `control/components.go` runs fixed bounded version probes on demand, caches results and detects binary replacement. Profiles describe implemented scope without expanding the privileged operation vocabulary. HAProxy's optional HTTP readiness fields use the existing closed v2 option record; the separate probe port cannot equal a traffic destination port. Realm's v3 record serializer retains its option field.

Version-1 records have 12 nonempty tab-separated fields:

`id, name, engine, protocol, bind, port, strategy, enabled, snat, interface, targets, schema_version`

HAProxy advanced settings use version 2 with a 13th options field. The first 12 fields retain their order, with `schema_version=2`. Options are closed, bounded semicolon-separated key/value data; old records load baseline defaults. Edits, enable/disable and snapshots preserve the field. Old manager releases cannot load v2 records; downgrade needs an appropriate v1 snapshot. See [HAPROXY.md](HAPROXY.md).

Only an absent default state is treated as a new installation. Explicit missing files, directories, dangling links and unreadable state fail closed; they must not reconcile as an empty configuration. CLI state inspection requires regular files, not streams.

Targets: comma-separated `IPv4:port@weight` or `[IPv6]:port@weight`. IDs: F plus six digits. Names: bounded ASCII. All fields are validated before rendering. Kernel target address families must match bind; relays can mix families. Canonical comparison keys make equivalent IPv6 spellings identical for listener conflicts, duplicate targets and direct self-loops; record spelling itself is preserved. Only kernel listeners can be separated by explicit entrance interfaces; relay sockets cannot. Files are never sourced/evaluated.

Mutations acquire flock, reload state, validate a candidate and preflight it before snapshotting and replacing the data file. Edits compare the current row against the exact row originally opened; a concurrent change requires reopening the editor. Preflight checks assigned addresses, existing entrance interfaces, IPv6 forwarding and native syntax checks for iptables/nftables/HAProxy without applying rules. Realm has schema/render validation only. Failure after state replacement atomically restores the previous state and attempts both kernel and relay reconciliation; recovery failure is reported. There is no globally atomic transaction across multiple kernel tables and systemd. Native nftables uses one batch; iptables uses per-table restore batches. Optional package installation occurs earlier and is not rolled back by this transaction.

`--validate` and `--plan` use readable state files without root or temporary files. Plans render desired enabled configs without probing destinations; they exclude old-resource cleanup and separate FRP instances. `--doctor` reads host status without active probes or mutation and returns nonzero for invalid saved state; unavailable optional tools are informational.

Legacy rules keep their ownership. Strict generated DNAT syntax is grouped for deletion. Duplicates are drained; shared SNAT/FORWARD lines and unknown manual lines are preserved when needed. Old listeners must not overlap new ones.

Realm advanced records use version 3 with the same 13-field layout and bounded network options: TCP/UDP timeout, keepalive/probes, PROXY send/version/accept/timeout and logging. Existing v1/v2 remain readable; older releases cannot read v3. Terminal edits retain options without needing a new terminal form.

The optional panel has typed capability contracts, an unprivileged public HTTP/HTTPS server, bcrypt sessions with CSRF/Origin checks, and a local root broker over a group-protected Unix socket. All forwarding writes use the Bash API and reload full state under the shared lock. Row revisions protect edits and bulk selection from stale requests. GRE and reverse adapters never receive arbitrary commands/config text.

## Runtime

- The Bash manager has no resident process. The explicitly installed Go web panel adds separate public HTTP/HTTPS and private broker services; optional metrics sampling runs only when enabled. See [WEB-PANEL.md](WEB-PANEL.md).
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


Panel installation is independent of runtime control. `panel/internal/setup` owns the quick/custom terminal flow and one-time bounded IP discovery; `panel/internal/config` validates addresses, protocols and passwords and persists config/certificates. Missing protocol fields preserve older HTTPS installations. The public server selects both its listener and cookie policy from that validated protocol. Origin checks use the actual direct HTTP/TLS connection, never an untrusted forwarded header. No browser transport setting changes tunnel-engine behavior or exposes the broker socket remotely.

## Optional Nodes and paired operations

`panel/internal/nodes` owns protocol contracts, private PKI, bounded registry storage, the dedicated TLS-only Controller listener and outbound Agent. `httpapi/nodes.go` exposes authenticated administrator enrollment/revocation and a local/remote inventory list. The normal broker remains local; Agent installations default to an inventory/capabilities-only broker. Explicit `--operations` additionally allows only typed leased-create tasks; it does not expose the general local operation vocabulary. No Node field is added to current operation requests. `nodes/pairs.go` persists Controller plans and advances their two-node state machine. `control/node_task.go` owns root receipts, idempotency and lease recovery; `src/pair_api.sh` compares revisions and resource fingerprints under the shared Bash lock. The frontend lazily loads `features/nodes` and preserves the shared visual/localization system. See [NODES.md](NODES.md) for authentication, limits, artifact ownership and migration boundaries.

Paired operations preflight both Nodes, apply entrance before destination, then require time-limited confirmation. Individual outcomes persist through Controller restarts; missing acknowledgments are redelivered to the broker receipt. Uncertain create outcomes and changed resources require inspection. There is no distributed atomic transaction. See [PAIRED-CONNECTIONS.md](PAIRED-CONNECTIONS.md).
