# Roadmap

This is a direction for future work, not a promise that every native engine feature is supported. The [capability matrix](ENGINE-CAPABILITIES.md) describes current adapters; the [changelog](CHANGELOG.md) records delivered work.

## Available in v1.3.2

- Terminal managers and a bilingual responsive web panel with compact forms, three setup presets per engine and configuration inspection/editing.
- Local GRE, kernel forwarding, HAProxy, Realm, FRP and rathole management, including bounded routing and transport options.
- Optional Nodes/Agents, coordinated GRE/FRP creation and read-only remote traffic summaries.
- Local traffic cycles, labels, reset, advisory quotas, optional history and CSV export.
- Versioned packages with embedded frontend and matching Bash helper; HTTP/HTTPS setup, upgrades and scoped removal.

## Priorities for the next iterations

| Priority | Proposed work | Acceptance before shipping |
| --- | --- | --- |
| 1 | Real-server rollout coverage | Two disposable VPSs; independent reboot, service ordering, provider firewall and interrupted-operation recovery under TCP/UDP traffic |
| 2 | Shared reverse-connection lifecycle | Versioned FRP/rathole state, secret references, edit/restore and migration tests; retain existing instances |
| 3 | Clearer network diagnostics and dependencies | On-demand bounded probes, route/MTU visibility and affected-resource preview; no automatic host-wide changes |
| 4 | Remote configuration/accounting actions | Separate typed capabilities, explicit opt-in, revisions, expiry, identity isolation and partial-failure recovery |
| 5 | Scheduled local traffic cycles | Explicit timezone/retention policy, restart-safe scheduling and confirmed reset semantics |

Automatic quota cutoffs need a defined connection-stop policy and counter-failure behavior. Current quotas remain advisory. Remote history, customer accounts, unrestricted HAProxy ACLs, Realm native TLS/WSS and arbitrary host firewall editing are not delivered features.

## Candidate methods

Consider WireGuard server links first, then a separate AmneziaWG adapter when there is a concrete deployment need. GOST chains and GRE-over-UDP may address specific routing/filtering scenarios. Each needs a versioned contract, ownership model, peer/MTU validation and recovery tests before entering the catalog. Forwarding traffic to an existing WireGuard service is already supported and is distinct from provisioning that link.

Keep the data path independent of the panel. Add background work only as an explicit option, and do not infer throughput, latency or memory guarantees from a language or transport choice.

Historical phased plans and completed reviews are preserved in the [archive](archive/README.md).
