# Engine capability and version matrix

The panel's **Tunnel engines** page shows installed versions, compatibility information, supported adapter features and limits. This describes the manager's adapters, not every native engine feature. Node protocol capabilities (`inventory.read`, `connections.pair.v1`) are a separate contract.

| Engine | Version policy | Managed features | Validation and boundaries |
| --- | --- | --- | --- |
| HAProxy | 2.4+ in 2.x, or 3.x; installed native check remains authoritative | TCP passthrough, SNI/HTTP routes, HTTPS termination, weighted balancing, TCP/HTTP readiness, checked failover, limits/timeouts, PROXY sending, compatible worker reload, optional bounded IP affinity | `haproxy -c` before apply; bounded exact-host SNI/HTTP routing and operator-provisioned HTTPS termination; no generic UDP, raw ACL editor or remote general CRUD |
| Realm | Installer pins 2.9.6; other 2.x are unverified | TCP/UDP, weighted round robin/source, timeouts, keepalive, PROXY send/accept, logging, pinned WS/MPTCP/IPv6-only profiles | Closed schema/render and feature/kernel checks; no native configuration dry run, active health checks or native TLS/WSS editor |
| nftables | Distribution package, compatible kernel required | Owned DNAT, weighted random/incremental/source-IP hash distribution, source policy, TCP MSS clamp | Native `nft --check`; no unrestricted host firewall editor or active target checks |
| iptables | Distribution package, compatible kernel required | Owned DNAT, weighted random distribution, source policy, TCP MSS clamp | Per-table restore validation; no host flush or active target checks |
| FRP | Installer pins 0.71.1; client/server must match | TCP/UDP services over TCP/WS/QUIC/local KCP, separate WSS gateway, bounded two-node setup | `frpc/frps verify`; coordinated pairing excludes KCP, WSS and custom certificates |
| rathole | Installer pins 0.5.0 | Reverse TCP/UDP services using the managed Noise NK/TCP preset | Closed schema and guarded startup; no remote pairing or other native transports |

Installed versions use fixed local command/argument pairs. Only bounded parsed strings reach the interface. The broker caches them for five minutes and invalidates on binary replacement. Local `frpc` and `frps` are checked separately; a mismatch is explicit. Remote peer versions are not inferred. The separate manual **Check versions** action reads official release metadata and configured distribution candidates; see [Engine maintenance](ENGINE-MAINTENANCE.md). No polling daemon is added. Existing Nodes can omit additive inventory fields without a protocol change.

Compatibility labels distinguish **pinned**, **native check required**, **unverified**, **unsupported**, **mismatch** and **unknown**. A recognized version is not proof of build options, kernel support, peer compatibility, backend readiness or vendor support lifecycle. Unknown output is not interpreted as compatibility. A pinned label identifies the selected release, not a claim to support every native feature. Native preflight remains required even for recognized versions. A five-minute cache may briefly retain a failed probe until expiration or binary replacement.

The registry is in `panel/internal/model/engines.go`; installed-version probing is in `panel/internal/control/components.go`. Forwarding protocols/options still come from the existing closed connection model. Profiles are informational and do not grant additional privileged operations or silently rewrite existing configurations. See [HAProxy](HAPROXY.md), [Nodes](NODES.md) and [paired operations](PAIRED-CONNECTIONS.md).

See [HAProxy routing](HAPROXY-ROUTING.md), [Realm profiles](REALM-PROFILES.md) and [traffic accounting](TRAFFIC-ACCOUNTING.md) for the new closed contracts and compatibility boundaries.

## Native features still outside the adapters

The upstream projects support a wider configuration language. These are extension candidates, not enabled features:

| Engine | Native capability | Required integration before enabling |
| --- | --- | --- |
| HAProxy | Dynamic DNS backends, per-source rate/connection limits, backend TLS/mTLS, persisted stick-table peers, arbitrary HTTP rules | Typed policies, secret/certificate ownership, native preflight, migration/reload tests |
| Realm | Native TLS/WSS, hostname/DNS policies, outbound `through`/interface options | Pinned build-feature checks, certificate validation, resolver lifecycle and real peer tests |
| iptables/nftables | General filter rules, sets/maps, marks/policy routing, rate limits | Separate ownership domain and conflict/rollback model; never replace the host firewall |
| FRP | STCP/XTCP/SUDP, HTTP(S) virtual hosts, visitor/plugin/OIDC/pool/bandwidth features | Separate client/server contracts, authentication boundaries and reverse lifecycle recovery |
| rathole | Plain TCP, native TLS and WS/WSS transports, custom heartbeat/retry/keepalive | Version/build gates, certificate/secret references, editable reverse state and recovery compatibility |

Priority for VPN use is dependable forwarding, clear source-affinity behavior and peer recovery before adding another transport selector. No transport is universally fastest: application protocol, packet loss, provider filtering and CPU budget determine the useful choice.

Primary references: [HAProxy manual](https://docs.haproxy.org/3.2/configuration.html), [Realm configuration](https://github.com/zhboner/realm#configuration), [FRP networking](https://gofrp.org/en/docs/features/common/network/network/), [rathole transport guide](https://github.com/rathole-org/rathole/blob/v0.5.0/docs/transport.md), [Netfilter projects](https://www.netfilter.org/).
