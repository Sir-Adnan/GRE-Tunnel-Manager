# Roadmap

This is a direction for future work, not a promise that every native engine feature is supported. The [capability matrix](ENGINE-CAPABILITIES.md) describes current adapters; the [changelog](CHANGELOG.md) records delivered work.

## Available in v1.4.0

- Terminal managers and a bilingual responsive web panel with compact forms, three setup presets per engine and configuration inspection/editing.
- Local GRE, kernel forwarding, HAProxy, Realm, FRP and rathole management, including bounded routing and transport options.
- Optional Nodes/Agents, coordinated GRE/FRP creation and read-only remote traffic summaries.
- Local traffic cycles, labels, reset, numeric quotas with optional sampled traffic pauses, bounded history and CSV export.
- Visible-only dashboard CPU, memory and default-route network rates with pause/cadence controls.
- Optional health monitoring (uptime, outages, weekly reports, conntrack and CPU pressure) and maintenance plans for refresh, restart and reboot with schedules, health triggers and guards.
- Health failover for balanced kernel forwards, HAProxy check results, per-destination connection counts, a GRE path MTU test and an Optimization page with reversible kernel settings that are never worse than the server's own values.
- Kernel forwards on every local address by default, so additional IPs work without per-address rules; replies for an address with its own gateway follow its routing table.
- A status-first overview, one filtered Connections page, a command palette and five appearance presets (Signal by default) at WCAG AA for the project presets.
- Versioned packages with embedded frontend and matching Bash helper; HTTP/HTTPS setup, upgrades and scoped removal.

## Priorities for the next iterations

Version v1.4.0 adds health failover and server optimization. Next: optimization profiles, change history with one-click rollback, scheduled local backups, a guided "why is this tunnel down" check, in-panel and webhook notifications, login hardening (TOTP, sessions, address allowlist), a read-only metrics endpoint, a multi-server health view through Nodes with probes from the far side, and an on-demand speed test between GRE ends.

Version v1.3.6 routes kernel-forward replies for additional IPs with their own gateway through that gateway, allows IPv4 and IPv6 kernel forwards on one port and extends the doctor report for multi-address hosts.

Version v1.3.5 fixes kernel forwarding on servers with additional IPs, hardens apply, state loading, login throttling and job polling, and redesigns the panel around a filtered Connections page, a needs-attention overview and a command palette. A guided GRE-plus-forward wizard and a route test remain proposals.

Version v1.3.4 adds compact direct-action connection lists, expanded typed native edits, reviewed HAProxy/Realm/managed-JSON imports, automatic HAProxy sizing, local FRP KCP and explicit engine maintenance. These do not expose every upstream directive or expand the existing Node operation protocol. See [Engine capabilities](ENGINE-CAPABILITIES.md) and [Engine maintenance](ENGINE-MAINTENANCE.md).

Version v1.3.3 adds the refactored panel workspace, HTTP-compatible copy controls and encrypted portable recovery on a fresh installation. Recovery does not yet merge with an occupied setup, schedule backups or migrate Controller/Agent identities.

| Priority | Proposed work | Acceptance before shipping |
| --- | --- | --- |
| 1 | Real-server rollout coverage | Two disposable VPSs; independent reboot, service ordering, provider firewall and interrupted-operation recovery under TCP/UDP traffic |
| 2 | Shared reverse-connection lifecycle | Versioned FRP/rathole state, secret references, edit/restore and migration tests; retain existing instances |
| 3 | Clearer network diagnostics and dependencies | On-demand bounded probes, route/MTU visibility and affected-resource preview; no automatic host-wide changes |
| 4 | Remote configuration/accounting actions | Separate typed capabilities, explicit opt-in, revisions, expiry, identity isolation and partial-failure recovery |
| 5 | Scheduled local traffic cycles | Explicit timezone/retention policy, restart-safe scheduling and confirmed reset semantics |

Explicit opt-in local quota pauses now use sampled detection and scoped kernel drop guards. Byte-exact kernel quota objects, reboot-independent enforcement and remote quota edits remain future work. Existing quotas stay advisory until opted in. Remote history, customer accounts, unrestricted HAProxy ACLs, Realm native TLS/WSS and arbitrary host firewall editing are not delivered features.

## Candidate methods

Consider WireGuard server links first, then a separate AmneziaWG adapter when there is a concrete deployment need. GOST chains and GRE-over-UDP may address specific routing/filtering scenarios. Each needs a versioned contract, ownership model, peer/MTU validation and recovery tests before entering the catalog. Forwarding traffic to an existing WireGuard service is already supported and is distinct from provisioning that link.

Keep the data path independent of the panel. Add background work only as an explicit option, and do not infer throughput, latency or memory guarantees from a language or transport choice.

Historical phased plans and completed reviews are preserved in the [archive](archive/README.md).
