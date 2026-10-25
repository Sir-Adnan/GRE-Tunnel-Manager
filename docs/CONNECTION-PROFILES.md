# Connection profiles

There are three setup presets per engine (21 total). Presets fill a draft; nothing changes until review and save. Existing connections retain their saved settings. Other supported transports, algorithms and limits remain in advanced controls.

New HAProxy connections explicitly use `maxconn=0`, `server_maxconn=0`, `check_mode=off` and `log=off`: automatic sizing, no per-target cap, no active checks and no traffic logs. New Realm connections use `log=off`. The browser and Go API share `model/creation_defaults.json`; terminal forms write matching options. Explicit operator values win. Existing records retain saved values and absent-key semantics.

Zero omits both HAProxy `maxconn` directives. HAProxy derives its limit from the service's file-descriptor budget (1048576 for automatic mode); this is not unlimited capacity or a memory reservation. An explicit cap uses a service budget of `2 * maxconn + 2048`. Capacity still depends on RAM, CPU, source ports, bandwidth and destinations. Finite connect/inactivity timeouts remain intentional: unlimited waits can retain broken sessions indefinitely. Engine logging choices do not disable panel security audits or startup errors.

The catalog is `panel/internal/model/presets.json`, embedded in the Go panel and exposed with local inventory. It supplies both language labels and bounded form values. It is not fetched remotely. Agents omit this UI catalog from inventory reports so presentation changes do not enlarge remote snapshots or affect their revisions.

## HAProxy

| Profile | Main choices |
| --- | --- |
| Balanced | Least connections with multiple targets, 1-hour idle window |
| Long-lived | Opaque TCP, 24-hour client/server/tunnel idle window |
| IP affinity | Long-lived TCP plus a bounded 16384-entry source-IP table with 1-hour expiry |

All three use automatic connection sizing, no per-target cap and logs off. Explicit caps remain available in advanced controls. No TLS termination or PROXY header is added automatically.

These profiles use TCP checks, two connect retries and 30-second client/server half-close timeouts. Selecting a preset replaces engine options and clears optional routing, so an old PROXY/HTTP-check/TLS choice cannot leak into a plain VPN preset. Review before saving. **Simple defaults** resets those options; **Custom settings** keeps the current draft for manual adjustment. Source addresses, names and destinations remain unchanged. A single target stays `single`; multi-target profiles choose the documented algorithm.

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
- **FRP:** TCP with multiplexing, QUIC and WSS are the three presets. TCP without multiplexing, WebSocket and local KCP remain in transport controls. Apply compatible choices at both peers. QUIC/KCP need a UDP path; KCP may consume extra bandwidth and is not universally faster. WSS needs operator certificates. KCP is not added to the existing Node pairing protocol.
- **rathole:** TCP, UDP or both over authenticated Noise/TCP. The UDP service still has a TCP outer transport; it is not native UDP/QUIC. Tokens/keys, peer addresses and ports remain explicit and are not replaced by profile selection.

Use the question-mark help for each profile's tradeoffs. Native feature/version gates and normal preflight still apply. A profile is not a way to enable unsupported engine options.
