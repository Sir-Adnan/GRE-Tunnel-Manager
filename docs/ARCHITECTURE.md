# Architecture

Form layout: `DialogBody` owns modal scrolling and the containing block for hidden absolute form controls; `FieldGroup columns` owns responsive form columns. `EngineOptionFields` groups typed adapter options without changing their schema. The traffic list delegates writes to the existing captured-target `TrafficActions` flow. See [Interface conventions](INTERFACE.md).

Portable recovery separates its authenticated envelope (`control/backup_crypto.go`), typed validation/migration and orchestration (`backup.go`), recognized adapter decoding (`backup_resources.go`) and paused publication (`src/recovery.sh`). Dedicated authenticated `/api/backups/*` routes use a single-request size gate and forward only fixed actions to the local `/backup` broker endpoint. They do not expand the Node operation vocabulary. The lazy frontend separates creation, restore orchestration, migration fields and scope/help; see [Backup and restore](BACKUP-RESTORE.md).

`model/creation_defaults.json` is embedded by Go and imported by Vite. Only create merges these defaults, with explicit values taking precedence. Reads, updates, configuration import and reconciliation retain legacy absent-key behavior. New terminal forms write matching explicit values. No Node protocol or broker action is added.

Modular Bash source is concatenated by `tools/build.py` into standalone `gre.sh`. Its `--check` also verifies that every release version copy matches `GTM_VERSION`. Runtime does not download/source modules. Sourcing the release defines functions/constants only; execution is guarded by `BASH_SOURCE[0] == $0`.

| Module | Responsibility |
| --- | --- |
| core | Bounded validators, endpoints, paths, privileges, flock |
| server_info | Session-cached host/address metadata and bounded optional public-IP/provider lookup |
| ui | Fixed ANSI styling, dedicated headers, numbered selectors and input rendering |
| haproxy_routing | Separate closed routing contract, operator PEM validation and bounded SNI/HTTP backends |
| metadata | Fingerprint-bound display-name sidecar; locked CAS updates and retirement |
| haproxy | Validated TCP options, rendering, local stats, worker readiness and settings UI |
| realm_options | Validated Realm network options with compatible v3 records |
| state | TSV records, conflicts, snapshots, apply/recovery |
| firewall | Owned iptables chains and native nftables table |
| relays | Optional component installation and Realm/HAProxy services |
| components | Fixed engine package policies, checked maintenance and staged pinned-binary publication/recovery |
| transports | FRP, transports and WSS TLS gateway |
| rathole | Pinned optional installer, Noise NK reverse connections, scoped services/removal |
| catalog | Offline capability guide and reverse-engine selection |
| inspect | Offline previews/validation, preflight, host health report, GRE dependencies |
| forms | Read-only staged setup, port lists, remote endpoints, optional details and batch save |
| optimize | Opt-in profiles and groups (conntrack, packet queues, relay TCP, routing, network card), journal with original values, undo steps, group restore and reset; drop-in sorts last, link keys replay through a boot unit |
| cleanup | Retirement of v13.x forwards, Simple GRE and old tuning files: closed inventory, backups, scoped deletion |
| links / reverse_api / pair_api / api | Noninteractive owned-resource operations shared with the Go panel |
| recovery | Typed, paused recovery with full staging, target-revision checks and checked file rollback; no imported executable units |
| history | Restore points as a change history; revision-checked restore through the normal commit |
| resolve | Domain destinations: cache and per-name policy, expansion to addresses at render time, minute refresh timer that reapplies only on change |
| portfw | Read-only export of Port Forward Manager rules and a listener guard while its NAT is active |
| sysdns | Server resolvers: systemd-resolved drop-in or rewritten resolv.conf with a boot unit, exact restore, terminal menu |
| diagnose | Read-only checks and probe targets for one connection or GRE tunnel |
| panel | Optional panel lifecycle and engine preinstallation menus |
| menus | Task menus, grouped CRUD, GRE through the shared `links` engine, diagnostics |

## Navigation

The main menu has eight sections: GRE Tunnel, Port Forwarding, HAProxy Tunnel, Realm Tunnel, Reverse Tunnel, Load Balancing, Tools and optional Web Panel. GRE has direct Kharej/Iran choices; these roles retain the original wire contract regardless of geography. HAProxy and Realm have dedicated branded managers for setup, balancing, list/edit/delete, start/stop and status/logs. The terminal and the panel create and delete GRE through the same `links` operations.

Engine menus use a dynamically scoped `GTM_ENGINE_FILTER` only in `gtm_records` presentation/selection. After selecting stable IDs, mutations reload the **entire** state under the lock and preserve other engines. Never pass a filtered presentation array directly to reconciliation. Styling is fixed, English-only and foreground-only, respecting NO_COLOR/non-TTY/dumb output. Old preferences are ignored and no preference file is created. Theme/language/layout switches are removed.

Headers show the host/OS, full public/local addresses and network provider/ASN/country. A large ASCII GRE banner is used only at widths of at least 68 columns and heights of at least 34 rows; other windows keep a compact title. Interactive setup steps redraw the header so addresses remain available. Local identity is read without sourcing OS files or sending route probes. One optional HTTPS request to ipwho.is, with a two-second deadline and 8 KiB response limit, supplies the outgoing public address and approximate network attribution. Only validated addresses and sanitized ASCII scalar fields are displayed; metadata never sets a bind or target. It is cached in process memory, including lookup failure, until Tools → Refresh Server Info. `GTM_SERVER_LOOKUP=0` disables the external request. Sourcing, previews, demo, inspection commands and noninteractive output never perform that lookup. No cache file, timer or daemon is created.

Setup collects local ports, remote address and remote port, then shows review. Protocols, transport, balancing and PROXY/log options are numbered. Names are generated; optional details are off the main path. Relays and kernel forwards default to all local addresses of the destination family (`0.0.0.0` or `::`). Servers with additional IPs therefore accept a forward on every assigned address. Kernel wildcard rules match `fib daddr type local` (nftables) or `-m addrtype --dst-type LOCAL` (iptables), not a pinned destination. Their companion SNAT/forward/MSS rules match the DNAT state, target and original port. An explicit bind keeps its exact `daddr`/`--ctorigdst` match. Wildcard preflight rejects a target matching a local address on its own listening port. Addresses whose source policy routing uses another table get a connection mark on entry. Replies restore it in a prerouting mangle-priority chain and follow an owned `fwmark` rule into that table (see [Operations](OPERATIONS.md)). Detection runs only in preflight, apply and doctor; offline previews render no marks.

One setup accepts up to 32 unique local ports, including bounded ranges. Each port becomes an independent existing-schema record and ID. The user chooses fixed destination port(s) or matching local/remote ports. The full batch is rendered/validated, then appended to freshly loaded full state under one lock, with one counter update and one commit/preflight/snapshot/apply. Editing remains single-record and preserves the old options/state/source policy. Service install is after review and outside rollback, as before.

## State

Engine adapter/version profiles live in `panel/internal/model/engines.go`, independently of Node transport capabilities. `control/components.go` runs fixed bounded version probes on demand, caches results and detects binary replacement. Profiles describe implemented scope without expanding the privileged operation vocabulary. HAProxy's optional HTTP readiness fields use the existing closed v2 option record; the separate probe port cannot equal a traffic destination port. Realm's v3 record serializer retains its option field.

Version-1 records have 12 nonempty tab-separated fields:

`id, name, engine, protocol, bind, port, strategy, enabled, snat, interface, targets, schema_version`

HAProxy advanced settings use version 2 with a 13th options field. The first 12 fields retain their order, with `schema_version=2`. Options are closed, bounded semicolon-separated key/value data; old records load baseline defaults. Edits, enable/disable and snapshots preserve the field. Old manager releases cannot load v2 records; downgrade needs an appropriate v1 snapshot. See [HAPROXY.md](HAPROXY.md).

Only an absent default state is treated as a new installation. Explicit missing files, directories, dangling links and unreadable state fail closed; they must not reconcile as an empty configuration. CLI state inspection requires regular files, not streams.

Targets: comma-separated `IPv4:port@weight`, `[IPv6]:port@weight` or `name:port@weight` (a DNS name, resolved at render time from `dns-cache.tsv`). Kernel records may use a port range (`2000-2999`) with targets on one port or on a range of the same length; see [Port ranges, domain destinations and server DNS](PORTS-AND-DNS.md). IDs: F plus six digits. Names: bounded ASCII. All fields are validated before rendering. Kernel target address families must match bind; relays can mix families. Canonical comparison keys make equivalent IPv6 spellings identical for listener conflicts, duplicate targets and direct self-loops; record spelling itself is preserved. Only kernel listeners can be separated by explicit entrance interfaces; relay sockets cannot. Files are never sourced/evaluated.

Loading indexes enabled listeners by port, so conflict detection is linear. Address keys are computed without subshells (`gtm_key_of` sets `GTM_KEY`). Mutations acquire flock, reload state, validate a candidate and preflight it before snapshotting and replacing the data file. After a successful apply, automatic restore points beyond `GTM_RESTORE_POINTS` (default 100) are pruned by exact generated name. Edits compare the current row against the exact row originally opened; a concurrent change requires reopening the editor. Preflight checks assigned addresses, existing entrance interfaces, IPv6 forwarding and native syntax checks for iptables/nftables/HAProxy without applying rules. Realm has schema/render validation only. Failure after state replacement atomically restores the previous state and attempts both kernel and relay reconciliation; recovery failure is reported. There is no globally atomic transaction across multiple kernel tables and systemd. Native nftables uses one batch; iptables uses per-table restore batches. Optional package installation occurs earlier and is not rolled back by this transaction.

`--validate` and `--plan` use readable state files without root or temporary files. Plans render desired enabled configs without probing destinations; they exclude old-resource cleanup and separate FRP instances. `--doctor` reads host status without active probes or mutation and returns nonzero for invalid saved state; unavailable optional tools are informational.

Legacy rules keep their ownership. Strict generated DNAT syntax is grouped for deletion. Duplicates are drained; shared SNAT/FORWARD lines and unknown manual lines are preserved when needed. Old listeners must not overlap new ones.

Realm advanced records use version 3 with the same 13-field layout and bounded network options: TCP/UDP timeout, keepalive/probes, PROXY send/version/accept/timeout and logging. Existing v1/v2 remain readable; older releases cannot read v3. Terminal edits retain options without needing a new terminal form.

The optional panel has typed capability contracts, an unprivileged public HTTP/HTTPS server, bcrypt sessions with CSRF/Origin checks, and a local root broker over a group-protected Unix socket. `control/actions.go` classifies each broker action as a read, public operation or backup action. That single registry drives the public `/api/operations` allowlist, broker locking and lifetime, audit filtering and `/backup` routing. Reads skip the mutation lock under a small concurrency bound; mutations stay serialized with a broker-owned ten-minute lifetime. All forwarding writes use the Bash API and reload full state under the shared lock. Row revisions protect edits and bulk selection from stale requests. GRE and reverse adapters never receive arbitrary commands/config text.

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

GRE keys, addressing, interface/unit names, IDs 1–250 and MTU 1430 remain compatible with v13.7+, so tunnels created by the old scripts keep working. Side A maps to old kharej, Side B to iran, irrespective of geography. The v13.x scripts (`gre-stable.sh`, `legacy/`), the old numbered menu and `--legacy` were removed in v1.4.0. GRE deletion is guarded by managed-record references to its interface or default internal address range (including disabled records). Unknown manual/legacy rules and custom routes are outside that guard; no forwards are automatically deleted.

**Tools → Retire old installation** removes recognized v13.x forwards, Simple GRE and old tuning files; bulk removal refuses unknown commands/custom units and no saved shell line is executed ([Retiring old installations](RETIRING-OLD-INSTALLS.md)). GRE setup writes no global sysctl. Server-wide kernel settings are opt-in groups with original values, undo and reset ([Server optimization](OPTIMIZATION.md)).


Panel installation is independent of runtime control. `panel/internal/setup` owns the quick/custom terminal flow and one-time bounded IP discovery; `panel/internal/config` validates addresses, protocols and passwords and persists config/certificates. Missing protocol fields preserve older HTTPS installations. The public server selects both its listener and cookie policy from that validated protocol. Origin checks use the actual direct HTTP/TLS connection, never an untrusted forwarded header. No browser transport setting changes tunnel-engine behavior or exposes the broker socket remotely.

## Optional Nodes and paired operations

`panel/internal/nodes` owns protocol contracts, private PKI, bounded registry storage, the dedicated TLS-only Controller listener and outbound Agent. `httpapi/nodes.go` exposes authenticated administrator enrollment/revocation and a local/remote inventory list. The normal broker remains local; Agent installations default to an inventory/capabilities-only broker. Explicit `--operations` additionally allows only typed leased-create tasks; it does not expose the general local operation vocabulary. No Node field is added to current operation requests. `nodes/pairs.go` persists Controller plans and advances their two-node state machine. `control/node_task.go` owns root receipts, idempotency and lease recovery; `src/pair_api.sh` compares revisions and resource fingerprints under the shared Bash lock. The frontend lazily loads `features/nodes` and preserves the shared visual/localization system. See [NODES.md](NODES.md) for authentication, limits, artifact ownership and migration boundaries.

Paired operations preflight both Nodes, apply entrance before destination, then require time-limited confirmation. Individual outcomes persist through Controller restarts; missing acknowledgments are redelivered to the broker receipt. Uncertain create outcomes and changed resources require inspection. There is no distributed atomic transaction. See [PAIRED-CONNECTIONS.md](PAIRED-CONNECTIONS.md).


## Routing, metadata and accounting

Routing is isolated in `model/routing.go` and `src/haproxy_routing.sh`; v4 appends a routing field after ordinary HAProxy options. Both validators enforce the same bounded grammar. Kernel nftables selection has random, incremental and fixed-seed source-IP hash profiles; no host policy editor is introduced. Extended Realm options require pinned-version feature checks and, for MPTCP, a compatible enabled kernel.

`resource-names.tsv` stores optional ASCII display names independently from GRE/reverse technical IDs. Inventory binds them to the unit content hash, and edits compare both the unit hash and old metadata-row hash under the manager's existing lock. Writes preserve the complete sidecar and create a previous-file backup. No network reload is needed for a display edit.

Traffic collection remains in `metrics.go`; cycle baselines, customer policies, bounded histories and pure ledger changes are in `traffic_ledger.go`. The public boundary exposes authenticated summary/history reads and allowlisted mutations. Mutations return small receipts to avoid retaining histories in the job cache. The browser's Traffic tabs separate usage from collection drafts; `TrafficActions` captures identity/revision at dialog opening. Frontend number/date formatters force Latin digits independently of locale. Primary button foreground correction is a user-approved style extension, leaving imported fill/source values unchanged.

## Optional remote traffic

`nodes/traffic.go` defines a separate bounded traffic-protocol-1 sideband over the existing active mTLS identity. Inventory and pair capability negotiation remain unchanged. Agents explicitly installed with `--traffic` read compact summaries from an accounting-enabled private broker; collection remains paused until enabled through the local root CLI. The broker uses the existing metrics engine and its own root ledger. The Controller retains one memory-only snapshot per identity, rechecks revocation after body decoding and does not persist or sum histories. Authenticated browser reads fetch one Node only. Node detail tabs mount/poll the read-only component only when selected and visible. See [Remote traffic summaries](REMOTE-TRAFFIC.md).

The overview uses `connections/ConnectionSummary.tsx`, a bounded five-row presentation separate from the full CRUD table. Container queries select a compact desktop row or two-row mobile composition. Data direction stays localized while IP/port values are isolated inline; destination disclosures share one component. No management selection or network state is copied into the overview.

The browser workspace uses allowlisted hash routes independent of Go API paths. `PanelHeader` owns shell controls; `ConnectionWorkspace` owns method-scoped lists. Connection draft state, basic fields, engine settings and review are separate modules; local resource setup lives in `features/resources`. Common discard protection and clipboard behavior remain outside engine forms. Secondary actions use accessible menus and public mutation contracts are unchanged. Editor/resource bundles load on demand; notifications are bundled frontend code, not a resident server service.

Configuration inspection/import is isolated in `control/configuration*.go`. Only closed IDs and revisions cross the public API. Native edits must round-trip through the same typed adapter; apply reuses the full-state Bash transaction. Reverse projections use a strict generated grammar and mask secrets. Local inventory embeds the static model profile catalog; remote Node snapshots omit UI catalog data.

`configuration_import.go` handles additive reviewed batches, with separate closed HAProxy/Realm decoders. It binds input and activation choice to a full server generation; `create-reviewed` rechecks that generation under the Bash lock before allocation. Kernel native edits extract typed single-destination data and must match the entire regenerated excerpt; raw rules never reach execution. `engine_releases.go` performs manual fixed-source metadata checks; `components.sh` owns maintenance with no Node-operation expansion. See [Engine maintenance](ENGINE-MAINTENANCE.md).

## Runtime statistics and quota control

`control/host_telemetry.go` owns bounded, on-demand procfs sampling and a shared sub-second cache, separately from inventory and the optional traffic ledger. `features/overview` owns polling/presentation; only a mounted visible dashboard polls, with aborts and no overlapping requests.

`internal/health` and `internal/maintenance` are pure packages: health turns probe results into status, rollups, outages and reports, and maintenance decides which plans are due under their triggers and guards. Neither starts goroutines or commands. `control/operations.go` adapts inventory to probe targets and plan owners; `control/broker_operations.go` runs the health and maintenance loops in the root broker and executes each step through `Manager.maintain`, which allows only managed `systemctl reload|restart`, the Bash `kernel-refresh` and `flows-reset` operations and `systemctl reboot`. Each step holds the mutation lock only for its command. Agent brokers construct no `Operations`. The browser modules are `features/health`, `features/maintenance` and the shared `features/operations` types and hooks; validation and summaries in `maintenance/plans.ts` mirror the Go rules and are unit-tested.

`traffic_quota.go` evaluates opt-in current-cycle quotas. The existing locked metrics reconciler adds per-resource kernel drops to the accounting table; ledger edits reconcile guards immediately. Collection selection cannot silently withdraw protection. Portable recovery disables automatic pause. See [Kernel and userspace](KERNEL-AND-USERSPACE.md) and [Traffic accounting](TRAFFIC-ACCOUNTING.md) for scope and operational limits.

## Notifications, snapshots and metrics

The Go package `notify` owns the bounded event list, settings with masked secrets, localized message text and one delivery worker (webhook and Telegram, retries, rate limit); it runs no commands. The broker's `Operations` emits events from health transitions, failover changes, maintenance runs, the optimization watch and scheduled snapshots. `control/snapshots.go` owns the snapshot schedule and files, `control/prometheus.go` the hashed token and text exposition (served at `/metrics` by the public server after the broker checks the token), `control/history.go` and `control/diagnose.go` parse the Bash engine's output and add probes. Notification read marks are "light" actions: their own lock, no mutation lock, no audit entry. See [Monitoring](MONITORING.md).
