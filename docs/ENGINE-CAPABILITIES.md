# Engine capability and version matrix

The panel's **Tunnel engines** page shows installed versions, compatibility information, supported adapter features and limits. This describes the manager's adapters, not every native engine feature. Node protocol capabilities (`inventory.read`, `connections.pair.v1`) are a separate contract.

| Engine | Version policy | Managed features | Validation and boundaries |
| --- | --- | --- | --- |
| HAProxy | 2.4+ in 2.x, or 3.x; installed native check remains authoritative | TCP passthrough, weighted balancing, TCP/HTTP readiness, checked failover, limits/timeouts, PROXY sending, compatible worker reload | `haproxy -c` before apply; no generic UDP, TLS/HTTP/ACL editor or remote general CRUD |
| Realm | Installer pins 2.9.6; other 2.x are unverified | TCP/UDP, weighted round robin/source, timeouts, keepalive, PROXY send/accept, logging | Closed schema/render checks; no native configuration dry run, active health checks, encrypted transport editor or MPTCP |
| nftables | Distribution package, compatible kernel required | Owned DNAT, weighted random distribution, source policy, TCP MSS clamp | Native `nft --check`; no unrestricted host firewall editor or active target checks |
| iptables | Distribution package, compatible kernel required | Owned DNAT, weighted random distribution, source policy, TCP MSS clamp | Per-table restore validation; no host flush or active target checks |
| FRP | Installer pins 0.71.1; client/server must match | TCP/UDP services over TCP/WS/QUIC, separate WSS gateway, bounded two-node setup | `frpc/frps verify`; coordinated pairing excludes WSS and custom certificates |
| rathole | Installer pins 0.5.0 | Reverse TCP/UDP services using the managed Noise NK/TCP preset | Closed schema and guarded startup; no remote pairing or other native transports |

Versions are discovered with fixed local command/argument pairs. Only bounded parsed version strings reach the interface; native output is not displayed. The broker caches the result for five minutes and invalidates it when the executable path, file size or modification time changes. The local `frpc` and `frps` binaries are checked separately; a local mismatch is explicit. This does not verify the FRP version running on a remote peer. No polling daemon or Internet lookup is added. Existing Nodes can omit the additive inventory fields without a Node protocol change.

Compatibility labels distinguish **pinned**, **native check required**, **unverified**, **unsupported**, **mismatch** and **unknown**. A recognized version is not proof of build options, kernel support, peer compatibility, backend readiness or vendor support lifecycle. Unknown output is not interpreted as compatibility. A pinned label identifies the selected release, not a claim to support every native feature. Native preflight remains required even for recognized versions. A five-minute cache may briefly retain a failed probe until expiration or binary replacement.

The registry is in `panel/internal/model/engines.go`; installed-version probing is in `panel/internal/control/components.go`. Forwarding protocols/options still come from the existing closed connection model. Profiles are informational and do not grant additional privileged operations or silently rewrite existing configurations. See [HAProxy](HAPROXY.md), [Nodes](NODES.md) and [paired operations](PAIRED-CONNECTIONS.md).
