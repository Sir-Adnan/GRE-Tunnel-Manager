# Notifications, diagnosis, metrics and tunnel tests

Version 1.4.1 adds tools that tell you when something breaks, why, and how good a tunnel is. Every one of them is off or on demand by default. None changes forwarding, firewall or kernel settings.

## Notification center

The bell in the panel header lists events, newest first, grouped by day, with an unread count. Selecting an event marks it read and opens the page it belongs to. The newest 300 events are kept in `/var/lib/gre-manager-panel/notifications.json` (mode 600).

| Event | Source | Severity |
| --- | --- | --- |
| A connection goes down / comes back | Health monitoring (owner status changes) | critical / info |
| Failover changes destinations | Health failover for kernel forwards | warning |
| Optimization undone automatically / kept | The optimization watch (see [Optimization](OPTIMIZATION.md#automatic-undo)) | warning / info |
| Maintenance finished / failed | Maintenance runs (dry runs excluded) | info / warning |
| Scheduled backup saved / failed | [Scheduled backups](BACKUP-RESTORE.md#scheduled-backups) | info / warning |

Each event carries its kind, an optional connection name, arguments for a localized detail (durations, destinations, names) and an untranslated technical detail as fallback. The panel and the external channels render the detail in English or Persian.

### Webhook and Telegram

**Settings → Notification channels** sends selected kinds to a webhook, a Telegram bot, or both. Defaults: outages, recoveries, automatic undo, failed maintenance and failed backups.

- **Webhook:** one `POST` per event with `Content-Type: application/json` and `User-Agent: gtm-panel/VERSION`. Body: `id`, `time`, `kind`, `severity`, `owner`, `name`, `detail`, `host`, and a ready message in `text` and `content` (Discord reads `content`, Slack and Mattermost read `text`). With a signing secret, `X-GTM-Signature: sha256=HEX` is the HMAC-SHA256 of the raw body.
- **Telegram:** `sendMessage` to a chat ID (`-100…`) or `@channel`. A self-hosted Bot API server or relay can replace `https://api.telegram.org` when this server cannot reach Telegram.
- Messages leave from this server through its default route; `HTTPS_PROXY` in the broker's environment is honored.
- Delivery: three attempts (now, after 10 s, after 1 min), 15 s each. At most 20 messages per 10 minutes; the rest stay in the panel and one summary follows. Each event shows Sent, Not delivered or Rate limited.
- The webhook URL, signing secret and bot token are stored root-only and never returned to the browser; leaving a field empty keeps the stored value, **Forget** removes it. **Send test** delivers a test event at once and reports failures per channel without echoing secrets.

## Guided diagnosis

**Diagnose** (Health row details, connection menu, GRE tunnel menu) answers "why isn't it working?" with a read-only checklist, problems first, each with a suggested fix:

| Connection | GRE tunnel |
| --- | --- |
| Enabled; IPv4/IPv6 forwarding (kernel forwards); kernel rules present (nftables table or iptables comments); failover exclusions; relay service active and port listening; connection-table pressure; route to each destination and whether its interface is down; a TCP connect (or, for UDP, a ping) to up to 8 destinations | Unit active; interface present and not down; local address still on the server; inner `/30` address; strict reverse-path filtering; an input policy that drops GRE (protocol 47) without an accept rule; connection-table pressure; ping to the peer's public address and through the tunnel |

The Bash engine (`gre.sh --api diagnose ID`) reports system checks and the endpoints to probe; the broker probes them with the health prober (3 s each, 8 s in total). The newest outage from Health is shown when monitoring is on. The far side's firewall can only be checked from that server; a paired Node reports it (below).

## GRE quality test

**Quality test** in a GRE row's details sends 20 pings, 200 ms apart, to the far end of the tunnel and shows average latency, jitter (mean difference between consecutive replies), loss and min–max, with one bar per ping. It takes about four seconds and needs nothing on the far side.

## Far-side checks and speed tests through Nodes

Agents from v1.4.1 send an optional **probe report** with each inventory report (`POST /v1/probes`, probe protocol 1): their CPU, memory and connection-table use, and for every GRE tunnel on the Node whether its interface is up and whether the far end answers a ping, with the round-trip time. The pings run in the Node's read-only local broker (`node-probes`), because the Agent itself is unprivileged. Older Controllers reject the endpoint and nothing else changes; `--probes=false` turns it off.

- **Nodes:** each card shows the Node's load and "N of M tunnels answer from this side"; **Details → Tunnels** lists every tunnel.
- **Health:** a local GRE tunnel that a Node also reports (same GRE ID, the Node's remote is one of this server's addresses) shows "Far side ✓ 41 ms" or "Far side ✗". A tunnel that answers here but not there points to a one-way block, usually a firewall.
- **Speed test** (Node details → Tunnels): the Controller offers a one-time 64-hex token, a port (20000–60999) and the Node's own inner tunnel address in its probe acknowledgment and asks for reports every 5 seconds. The Agent checks the address is one of its tunnel addresses, listens there for at most 45 seconds, accepts one connection with the token, counts 5 seconds of upload, reports the count, sends 5 seconds of download and closes. Both directions are measured by the receiver. It needs the Node to check in (up to a minute) and a firewall that allows the port on the tunnel address. Results are Mbit/s of TCP through the tunnel, not a guarantee for every flow.

## Prometheus metrics

**Settings → Metrics export** turns on a read-only `/metrics` endpoint in the Prometheus text format (version 0.0.4). It is off by default; enabling it issues a bearer token shown once (only its SHA-256 is stored in `/var/lib/gre-manager-panel/prometheus.json`). **New token** replaces it. The endpoint needs no panel session, answers 401 for a missing or wrong token and shares the panel's request limit. Over HTTP the token travels unencrypted: scrape over a private network or enable HTTPS.

```yaml
scrape_configs:
  - job_name: tunnel-manager
    scheme: https
    metrics_path: /metrics
    authorization:
      credentials: gtm_…
    static_configs:
      - targets: ["panel.example.com:2053"]
```

| Metric | Labels | Meaning |
| --- | --- | --- |
| `gtm_info` | `version`, `host` | Always 1 |
| `gtm_health_enabled`, `gtm_health_open_outages` | | Monitoring state, open outages |
| `gtm_connection_up` | `id`, `name`, `engine` | 1 up, 0.5 degraded, 0 down; unknown is omitted |
| `gtm_connection_latency_milliseconds`, `gtm_connection_uptime_ratio_24h` | same | Probe RTT, share of healthy checks |
| `gtm_traffic_received_bytes_total`, `gtm_traffic_sent_bytes_total` | `id` | Current traffic cycle (resets with the cycle) |
| `gtm_conntrack_entries`, `gtm_conntrack_limit`, `gtm_host_softirq_percent`, `gtm_host_steal_percent` | | From the last health sample |
| `gtm_host_cpu_percent`, `gtm_host_memory_total_bytes`, `gtm_host_memory_available_bytes`, `gtm_host_network_receive_bytes_per_second`, `gtm_host_network_transmit_bytes_per_second` | | Host telemetry |
| `gtm_notifications_unread` | | Unread panel notifications |

Health, traffic and conntrack values are only as fresh as the features that collect them; turn on Health monitoring and traffic collection for useful series.

## Evidence

Local tests cover event recording, bounds, persistence, secret masking, webhook signatures and Telegram delivery against a test server, localized details, the diagnosis parser and Bash checks with mocked tools, quality statistics, probe and speed-test contracts and a loopback speed test, the Prometheus token and exposition. They do not prove delivery through a real provider network, a speed test between two VPSs or far-side checks through real firewalls.
