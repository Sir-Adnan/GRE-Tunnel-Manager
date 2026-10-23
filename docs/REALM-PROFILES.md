# Realm extended profiles

These profiles are verified against the upstream [Realm v2.9.6 configuration](https://github.com/zhboner/realm/blob/v2.9.6/src/conf/net.rs), [endpoint schema](https://github.com/zhboner/realm/blob/v2.9.6/src/conf/endpoint.rs) and [WebSocket example](https://github.com/zhboner/realm/blob/v2.9.6/examples/ws.toml). They extend the existing closed v3 option record; baseline TCP/UDP behavior is unchanged.

| Option | Default | Scope |
| --- | --- | --- |
| `send_mptcp` | `false` | Outgoing TCP socket uses MPTCP |
| `accept_mptcp` | `false` | Incoming TCP listener uses MPTCP |
| `ipv6_only` | `false` | Disallow IPv4-mapped clients on an IPv6 listener |
| `listen_transport` | `plain` | `plain` or `ws` on the incoming TCP connection |
| `remote_transport` | `plain` | `plain` or `ws` on the outgoing TCP connection |
| `ws_host` | `localhost` | Bounded ASCII WebSocket Host |
| `ws_path` | `/` | Bounded ASCII WebSocket path |

Use Advanced settings in the Realm form. Both sides must agree on the selected transport. A typical pair has `remote_transport=ws` on the entrance and `listen_transport=ws` on the destination, with matching Host/path. WS is **unencrypted**; use a trusted path or a separately configured secure transport. This milestone does not expose Realm's native TLS/WSS strings, insecure verification flags, raw transport directives or automatic peer setup.

Extended profiles require the exact installed version 2.9.6. The official version output is `Realm 2.9.6 [features]`; case and trailing feature flags are handled. WebSocket additionally requires the binary's `[transport]` feature marker, so a slim/custom binary cannot silently ignore the transport option. Baseline installation still accepts existing Realm 2.x without replacing it, but unverified versions cannot use extended profiles.

MPTCP requires kernel support and `net.mptcp.enabled=1`; preflight checks this without changing global sysctls. Remote support and network policy determine whether a connection negotiates MPTCP or falls back to TCP. This is not a bandwidth aggregation guarantee. MPTCP options are rejected for UDP-only traffic; WS requires TCP-only traffic. IPv6-only requires an IPv6 bind address.

Realm does not expose a native configuration dry-run in this adapter. Schema validation, pinned-feature checks and the existing guarded service-start/recovery path apply. The capability page continues to label this limitation. Native active health checks/failover, generic remote CRUD, DNS configuration and unrestricted firewall editing remain outside these profiles.
