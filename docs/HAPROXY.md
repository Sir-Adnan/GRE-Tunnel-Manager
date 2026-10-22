# HAProxy TCP adapter — v1.2.0

The manager controls HAProxy Community as an optional local TCP relay. It does not implement a tunnel wire protocol, generic UDP forwarding, HTTP routing or TLS termination in this adapter. Existing Reality/TLS application bytes pass through unchanged unless the operator explicitly enables a supported PROXY header at both ends.

## Implemented capabilities

| Capability | Behavior |
| --- | --- |
| Targets | 1–32 validated literal IPv4/IPv6 endpoints, independent target ports, weights 1–256 |
| Balancing | Single, weighted round robin, leastconn, consistent source hash, primary plus ordered backup targets |
| Health | TCP connect checks, adjustable interval/timeout, fall/rise and optional alternate port |
| Timeouts | Separate connect, client/server inactivity and queue waits |
| Limits | Global/frontend maxconn, optional per-server maxconn; unit FD budget derived from maxconn |
| Recovery | Optional slow start; connect retries/redispatch; no automatic replay of established application sessions |
| Metadata | Optional outbound PROXY v1/v2; default off, no public accept-proxy listener |
| Logs | Connections, errors-only or off; output to journal/stdout rather than a manager log collector |
| Status | Root-restricted Unix stats socket, read-only role; target state/sessions/queue/check result on demand |
| Configuration changes | Native `haproxy -c`, managed snapshot/rollback, master-worker reload where unit compatibility allows; readiness requires a different worker PID |

TCP checks prove port reachability only. A separate check port can represent an application's dedicated readiness endpoint, but this preset still performs a TCP connect, not an HTTP request or a VPN handshake. Failover selects destinations for new connections and failed connect attempts; it cannot move an already established TCP session to a different server. Slow start is most useful with dynamic scheduling such as round robin/leastconn; hash scheduling has different distribution behavior.

The source strategy hashes the source IP observed by HAProxy. If traffic reaches it through another NAT, this can concentrate clients behind that NAT onto one target. We do not accept a user-supplied source header from public clients.

## Settings and record compatibility

Open **Traffic connections → HAProxy settings & status**. Settings are staged in memory until confirmation. The long-lived preset changes only idle timeout and log level, retaining other current choices. Balanced defaults explicitly reset staged values.

Version-1 records retain their 12 fields and load the baseline defaults. An advanced HAProxy save writes version 2 with the same first 12 fields (`version=2`) and a 13th field of semicolon-separated `key=value` options. Only the HAProxy engine accepts version 2. Missing optional keys use defaults; duplicate/unknown keys, empty values, control characters, out-of-range integers and raw config snippets are rejected. No data is sourced or evaluated.

| Key | Default | Allowed values |
| --- | --- | --- |
| connect | 5 | 1–300 seconds |
| idle | 3600 | 10–604800 seconds of inactivity, not a total session lifetime |
| queue | 30 | 1–3600 seconds |
| maxconn | 16384 | 1–100000; resource limit, not a capacity claim |
| server_maxconn | 0 | 0–100000; 0 disables this per-target cap |
| check_interval | 3 | 1–300 seconds |
| check_timeout | 5 | 1–300 seconds |
| check_fall / check_rise | 3 / 2 | 1–20 |
| check_port | 0 | 0 uses the target port; otherwise 1–65535 |
| slowstart | 0 | 0–3600 seconds; 0 disables it |
| proxy | off | off / v1 / v2 |
| log | connections | connections / errors / off |

Edits, enable/disable and snapshots preserve the option field. Older manager releases reject v2 records; use a suitable v1 snapshot for a deliberate downgrade. Component versions are independent of record/manager versions. Rendering is checked with the installed HAProxy, so unsupported directives fail preflight rather than being silently ignored.

## Local status and service lifecycle

```bash
sudo bash gre.sh --haproxy-status F000001
sudo journalctl -u gtm-F000001.service -n 100 --no-pager
```

The socket is `/run/gre-manager/haproxy/F000001.sock`, in a mode-700 directory with mode 600 and `level user`. No admin command or TCP stats endpoint is exposed. `socat` plus `timeout` perform bounded local queries; no Python runtime or additional daemon is used. Status counters belong to a worker and can reset on reload. Unavailable sockets are reported; a configured/active service is not automatically called healthy.

The dedicated unit uses master-worker foreground mode (`-W -db`). For a configuration-only update with an identical unit and a readable current worker PID, the manager validates the candidate, reloads via SIGUSR2 and waits for a different PID from the new worker's socket. Old sessions can drain on the previous worker. A missing/unreadable old socket, engine/unit upgrade or FD-limit change requires restart. Disable/removal uses a graceful stop signal with a 30-second systemd stop bound, after which remaining processes can be killed. Repeated reloads while very long sessions remain can retain multiple old workers and increase RAM; avoid unnecessary updates under load. There is no universal zero-downtime claim.

Native validation happens before replacing managed state. The broader transaction attempts recovery of both kernel and relay resources after failure. It is not atomic across systemd, kernel and files, and cannot recreate disconnected sessions. A failed readiness check reports failure even if an old master remains active.

## Still missing and recommended next

1. **Application health profiles:** HTTP readiness URL/status or explicitly defined safe TCP send/expect, separate from data TLS passthrough. Requires strict path/header validation and tests against a reachable-but-unhealthy backend.
2. **Per-target roles/maintenance:** durable target identity, individual primary/backup/drain states and weight changes. First model them in versioned state; do not expose arbitrary admin socket commands that disappear on restart.
3. **TLS transport profiles:** optional verified TLS to the destination and optional TLS termination for services designed for it. Certificate/CA/SNI lifecycle must be explicit. Terminating Reality traffic as ordinary HTTPS is not a compatible default.
4. **SNI passthrough routing:** multiple normal TLS services on one listener, with explicit default/unknown-name behavior. Requires a routing schema and ClientHello inspection timeout; do not equate hostname routing with universal VPN protocol detection.
5. **DNS targets:** resolvers, address-family preferences, TTL/failure behavior and stale-address handling. Current targets are literal IPs, which avoids silently changing destinations on DNS updates.
6. **Connection abuse controls:** optional per-source connection/rate caps via stick tables. NAT can group many legitimate clients behind one address; policies need workload-aware defaults and a clear rejection reason.

HTTP/WebSocket reverse proxying, caches and compression belong to a separate HTTP adapter. Generic UDP needs a suitable existing kernel/Realm/FRP/rathole path; this TCP adapter does not become a UDP relay by changing a menu label. Keep kernel NAT available when its routing/source semantics better fit the requirement.

## Primary references

- [HAProxy configuration manual](https://docs.haproxy.org/3.0/configuration.html) — timeouts, caps, balancing, slow start, checks, stats permissions.
- [Master-worker lifecycle](https://docs.haproxy.org/3.0/management.html) — SIGUSR2 reload and management socket behavior.
- [TCP and application health checks](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/health-checks/).
- [PROXY protocol requirements](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/proxying-essentials/client-ip-preservation/enable-proxy-protocol/).
