# Connection profiles

v1.3.1 provides 23 built-in profiles across forwarding, GRE and reverse transports. Select a profile in the setup form, adjust the details and review before applying. A profile fills a draft; selecting it never changes an existing service automatically. Existing connections open as **Custom / current settings** and are not migrated to a new preset.

The catalog is `panel/internal/model/presets.json`, embedded in the Go panel and exposed with local inventory. It supplies both language labels and bounded form values. It is not fetched remotely. Agents omit this UI catalog from inventory reports so presentation changes do not enlarge remote snapshots or affect their revisions.

## HAProxy

| Profile | Main choices |
| --- | --- |
| Balanced TCP | Least connections with multiple targets, 1-hour idle, 8192 max connections, errors-only logs |
| VPN / Reality | Opaque TCP, 24-hour client/server/tunnel idle window, shorter queue, no content inspection or TLS termination enabled |
| VPN with IP affinity | VPN settings plus a bounded 16384-entry source-IP table with 1-hour expiry |
| Primary + backup | First destination primary, other targets backup; checked new-connection failover |
| Small server | 2048 connection ceiling, 1-hour idle window, logs off |

These profiles use bounded TCP checks, two connect retries and 30-second client/server half-close timeouts. They retain explicit PROXY/readiness/TLS-routing fields rather than silently removing them; review any existing advanced settings. They do not enable TLS termination or a PROXY header automatically. A single target stays `single`; multi-target profiles choose the documented algorithm.

The new optional `fin` (0–300 seconds), `tunnel` (0–604800 seconds) and `retries` (0–5) adapter keys keep old defaults when absent: omitted FIN/tunnel overrides and three retries. New preset defaults apply only when selected. A nonzero tunnel timeout can supersede client/server idle windows for tunneled streams. Zero means preserve the native inherited/default behavior for the timeout override, not an unlimited timeout request.

Source-IP affinity is bounded in-memory routing for new connections, not a VPN account/session database. Shared NAT/proxy addresses share one mapping. Reload/restart clears the table; failed live TCP sessions must reconnect. Failover does not move an established stream to another server. TCP connect checks do not prove that Reality credentials, a VPN handshake or application routing works. Use a separate supported readiness endpoint where appropriate.

Native behavior: [HAProxy configuration manual](https://docs.haproxy.org/3.0/configuration.html), especially stick tables, retries, keepalives and tunnel/half-close timeouts. These are starting profiles, not universal latency, throughput or RAM guarantees. Size connection limits and affinity capacity for the actual host and route.

## Other forwarding engines

- **Realm:** TCP VPN, UDP WireGuard/AmneziaWG and mixed TCP/UDP. They set explicit network timeouts/keepalive/log values and reset TCP transport extensions to plain. UDP uses a 120-second relay association window; it is not a host conntrack sysctl. Source hashing has no active health-check failover. PROXY settings remain explicit and require a compatible receiver.
- **nftables:** direct TCP distribution or source-hashed UDP, with no userspace relay or new health checker. Multi-destination VPN endpoints need compatible keys/session behavior; source IP is not a user identity.
- **iptables:** direct TCP distribution or single-destination UDP. The UDP profile is unavailable with multiple targets because this adapter has no source-affinity selector. Use the normal validated form for other supported distributions.

Profiles do not change host-wide TCP/UDP conntrack timeouts, routes, forwarding sysctls, NIC settings or logging for unrelated software. Existing source policy/interface/address choices remain under the operator's control.

## GRE and reverse

- **GRE:** MTU 1430, 1400 or 1280. Select compatible values at both peers and verify the real path. This does not discover PMTU, encrypt GRE or guarantee fewer drops.
- **FRP:** TCP with/without multiplexing, UDP over QUIC, TCP over WebSocket, and WSS. Apply compatible transport choices at both peers. QUIC needs a usable UDP path. WSS requires the existing operator certificate/CA setup. Multiplexing shares the outer transport and can reduce socket count; its effect under loss depends on the route.
- **rathole:** TCP, UDP or both over authenticated Noise/TCP. The UDP service still has a TCP outer transport; it is not native UDP/QUIC. Tokens/keys, peer addresses and ports remain explicit and are not replaced by profile selection.

Use the question-mark help for each profile's tradeoffs. Native feature/version gates and normal preflight still apply. A profile is not a way to enable unsupported engine options.
