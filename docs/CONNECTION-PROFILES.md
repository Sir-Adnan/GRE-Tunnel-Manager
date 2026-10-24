# Connection profiles

There are three setup presets per engine (21 total). Presets fill a draft; nothing changes until review and save. Existing connections retain their saved settings. Other supported transports, algorithms and limits remain in advanced controls.

New HAProxy connections explicitly use `maxconn=100000`, `server_maxconn=0` and `log=off`. New Realm connections use `log=off`. The browser and Go API share `model/creation_defaults.json`; new terminal forms write matching options. Explicit operator values win. Existing records retain saved values and absent-key semantics.

A 100000 ceiling permits connections; it does not guarantee capacity. The managed HAProxy service descriptor budget is `2 * maxconn + 2048`. Real capacity also depends on RAM, CPU, bandwidth, available source ports and destinations. Reduce the cap for small servers. This neither allocates 100000 active sessions nor changes host tuning. Maximizing every timeout, queue and retry count can increase latency and resource retention; unspecified options retain the compatible baseline. Engine logging choices do not disable panel security audits or service startup errors.

The catalog is `panel/internal/model/presets.json`, embedded in the Go panel and exposed with local inventory. It supplies both language labels and bounded form values. It is not fetched remotely. Agents omit this UI catalog from inventory reports so presentation changes do not enlarge remote snapshots or affect their revisions.

## HAProxy

| Profile | Main choices |
| --- | --- |
| Balanced | Least connections with multiple targets, 1-hour idle window |
| Long-lived | Opaque TCP, 24-hour client/server/tunnel idle window |
| IP affinity | Long-lived TCP plus a bounded 16384-entry source-IP table with 1-hour expiry |

All three use a 100000 ceiling, no per-target cap and logs off. Primary/backup remains in the balancing selector; lower connection limits remain in advanced controls. No TLS termination or PROXY header is added automatically.

These profiles use bounded TCP checks, two connect retries and 30-second client/server half-close timeouts. They retain explicit PROXY/readiness/TLS-routing fields rather than silently removing them; review any existing advanced settings. They do not enable TLS termination or a PROXY header automatically. A single target stays `single`; multi-target profiles choose the documented algorithm.

The new optional `fin` (0–300 seconds), `tunnel` (0–604800 seconds) and `retries` (0–5) adapter keys keep old defaults when absent: omitted FIN/tunnel overrides and three retries. New preset defaults apply only when selected. A nonzero tunnel timeout can supersede client/server idle windows for tunneled streams. Zero means preserve the native inherited/default behavior for the timeout override, not an unlimited timeout request.

Source-IP affinity is bounded in-memory routing for new connections, not a VPN account/session database. Shared NAT/proxy addresses share one mapping. Reload/restart clears the table; failed live TCP sessions must reconnect. Failover does not move an established stream to another server. TCP connect checks do not prove that Reality credentials, a VPN handshake or application routing works. Use a separate supported readiness endpoint where appropriate.

Native behavior: [HAProxy configuration manual](https://docs.haproxy.org/3.0/configuration.html), especially stick tables, retries, keepalives and tunnel/half-close timeouts. These are starting profiles, not universal latency, throughput or RAM guarantees. Size connection limits and affinity capacity for the actual host and route.

## Other forwarding engines

- **Realm:** TCP, UDP and TCP + UDP. Presets use native timeouts/keepalive with logs off and plain transport extensions. UDP uses a 120-second relay association window, not global conntrack tuning. Source hashing has no active failover. Explicit PROXY choices require a compatible receiver.
- **nftables:** TCP, UDP affinity and single-destination TCP + UDP. No userspace relay or active checker is added. VPN destination keys/session behavior must be compatible; source IP is not a user identity.
- **iptables:** TCP, single-destination UDP and single-destination TCP + UDP. The latter two presets are unavailable with multiple targets because this adapter has no source affinity. Other supported distributions remain available in the normal form.

Profiles do not change host-wide TCP/UDP conntrack timeouts, routes, forwarding sysctls, NIC settings or logging for unrelated software. Existing source policy/interface/address choices remain under the operator's control.

## GRE and reverse

- **GRE:** MTU 1430, 1400 or 1280. Select compatible values at both peers and verify the real path. This does not discover PMTU, encrypt GRE or guarantee fewer drops.
- **FRP:** TCP with multiplexing, QUIC and WSS are the three presets. TCP without multiplexing and WebSocket remain in transport controls. Apply compatible choices at both peers. QUIC needs a UDP path; WSS needs operator certificates. Multiplexing shares the outer transport; its effect under loss depends on the route.
- **rathole:** TCP, UDP or both over authenticated Noise/TCP. The UDP service still has a TCP outer transport; it is not native UDP/QUIC. Tokens/keys, peer addresses and ports remain explicit and are not replaced by profile selection.

Use the question-mark help for each profile's tradeoffs. Native feature/version gates and normal preflight still apply. A profile is not a way to enable unsupported engine options.
