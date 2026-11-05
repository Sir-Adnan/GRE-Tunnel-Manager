# Health monitoring and maintenance

The web panel's **Health** and **Maintenance** pages are optional and independent. Both are off on a new or upgraded installation. While off they start no probes, subprocesses or disk writes; the broker only reads one in-memory setting per second.

## Health monitoring

Turn it on with the switch on **Health**. Each round checks, from this server:

| Target | Check |
| --- | --- |
| Enabled TCP or TCP/UDP connection | One TCP connection per destination, closed before any payload is sent |
| Enabled UDP-only connection | One ICMP echo per destination (the port itself cannot be tested without a protocol) |
| HAProxy connection | Its systemd unit state; destinations use HAProxy's own health check (status, check time, sessions, backup) read from its stats socket, or one TCP connection when checks are off |
| Realm connection | Its systemd unit state |
| GRE link | Its unit state and one ping to the peer's inner address, read from the owned unit (`10.0.ID.1`/`.2`; legacy units are read the same way) |
| FRP / rathole instance | Its unit state |

Defaults: every 30 seconds, down after 3 consecutive failures, up again after 2 successes, degraded above 300 ms, 30 days of history. All of these are in **Settings** (10–300 s, 1–10 checks, 0 or 20–5000 ms, 1–90 days). Service units have no packet loss to smooth, so one failed state marks them down at once.

A tunnel with several destinations is **down** when all of them are down and **degraded** when some are. An outage starts at the first failed check of the streak that crossed the threshold and ends when the target recovers, is removed from the configuration or monitoring is turned off. Uptime counts checks whose resulting status was not down, so a single lost probe does not cost uptime.

The page shows:

- **Status**: one row per tunnel with current status, latency sparkline, 24 hourly cells and 24 h / 7 d / 30 d uptime. Expanding a row shows each check, its last error, the share of failed checks in 24 hours (packet loss for pings), who checked it (this panel or HAProxy) and 30 daily cells. nftables forwards with several destinations also show **new connections per destination**, and GRE links a **path MTU test** (both below).
- **Outages**: newest first, with an ongoing-only filter.
- **Weekly report**: calendar weeks in the maintenance time zone, starting Saturday in Persian and Monday in English. It shows uptime, outages (overlapping destinations are merged, not summed), downtime, latency average, peak and jitter, server load and conntrack peak, maintenance runs and, when [traffic accounting](TRAFFIC-ACCOUNTING.md) history exists, per-tunnel traffic. Export it as CSV or print it. Hourly rollups are UTC hours, so a week boundary in a half-hour time zone is accurate to 30 minutes.
- **Server**: conntrack usage, hash buckets, idle-TCP timeout and drops since the previous check, plus CPU, steal, softirq and I/O wait shares, all read from `/proc` and `/sys`.

### Choices in the forms

Connection and GRE forms have a **Health and protection** section, and GRE cards a shield button with the same choices:

- When health checks are off, one switch turns them on with the current settings as the form is saved.
- **Monitor this connection** (on by default) adds or removes the owner from the `ignore` list; ignored owners are not probed and show a grey dot.
- **Automatic failover** adds a kernel forward that ends up with two or more destinations (domains count their resolved addresses) to the failover list.
- **Notify me** removes the owner from the `quiet` list; quiet owners' outages stay in the notification center but are not sent to the webhook or Telegram.
- **Safe apply** (connections) keeps the restore point taken before the change and reverts to it after 2, 5 or 10 minutes unless *Keep changes* is pressed in the banner. The broker checks every 30 seconds, reverts through the change history only if the configuration revision is still the one right after the change, and emits a `change-reverted` notification either way. The pending change survives a broker restart in `safe-change.json`.

### Failover for kernel forwards

nftables and iptables spread new connections with a fixed rule (`numgen`, `jhash` or `statistic`) and do not check destinations, so a dead destination keeps its share of new connections. With a source-hash spread its users stay on the dead one. Health failover fixes this per forward (**Settings → Failover for kernel forwards**, off by default):

- Destinations of selected forwards are probed every 5 seconds (2–30 s), with the normal failure and recovery thresholds: three failures take a destination out in about 15 seconds.
- A destination that is down leaves the distribution map; its chain, NAT, MSS and accept rules stay so established flows continue if it answers. Its tracked flows are then cleared (one `conntrack -D` per destination), so clients reconnect to a live destination at once instead of waiting for a timeout. This needs the `conntrack` package; without it, stale flows expire on their own.
- At least one destination always stays. If every destination is down, nothing is excluded.
- When the destination answers again (two successes), it returns to the map.
- Exclusions live in `/run/gre-manager/excluded.tsv` (cleared at boot) and are bound to the forward's exact destination list: an edit or a reboot brings every destination back. The saved configuration never changes. Turning monitoring off clears every exclusion.
- With a source-hash spread, removing a destination also remaps some users of the other destinations, for new connections only.

The Status row shows a Failover badge and the expanded row which destinations are out, since when and any error. Each change is audited (`health-failover`). Failover is a kernel-forward feature; HAProxy already removes a failing destination after its own checks (default every 3 s, down after 3) and Realm has no destination checks.

### New connections per destination

For an nftables forward with several destinations, **Show distribution** reads one counter per destination chain from the owned table. Those chains hang off the NAT hook, which sees only the first packet of each connection, so the counters are new connections since the forward's rules were last applied. A destination far below the others is usually down or slow. Nothing runs until the button is pressed.

### Path MTU test

For a GRE link, **Test MTU** sends at most 24 ICMP echoes with Don't Fragment set (`IP_PMTUDISC_PROBE`) to the peer's inner address and finds the largest packet that gets a reply between 1200 bytes and the interface MTU. A result below the interface MTU means larger packets are dropped on the path; set the tunnel's MTU to the result on both servers. It takes a few seconds and runs only on request.

### Server pressure

High ping and jitter that build up over hours and disappear after a reboot usually come from connection tracking. Kernel forwards keep one conntrack entry per client connection. With the kernel default of keeping idle TCP entries for five days, abandoned VPN connections fill the table, lookups slow down when the limit is far above the hash size, and new connections are dropped once it is full. The Server tab names these conditions:

| Hint | Condition |
| --- | --- |
| Idle TCP kept for days | `nf_conntrack_tcp_timeout_established` ≥ 1 day |
| Table above 80 % | `nf_conntrack_count / nf_conntrack_max` |
| Drops | `drop`, `early_drop` or `insert_failed` increased in `/proc/net/stat/nf_conntrack` |
| Undersized hash table | limit more than 8 × `hashsize` |
| CPU steal ≥ 10 % | the provider's host is busy; outside this server's control |
| Softirq ≥ 25 % | packet processing dominates CPU |

Health itself changes no kernel setting. The hints link to the [Optimization](OPTIMIZATION.md) page, whose Connection tracking group addresses the first, second and fourth, and Packet queues the last.

### Cost

A round with ten destinations opens ten short TCP connections or pings and reads a few `/proc` files; HAProxy destinations cost one stats-socket read per instance instead. Failover adds a 5-second round for the selected forwards' destinations only, and a kernel rule reapply only when a destination changes state. Inventory, which runs the Bash helper and `systemctl show`, is refreshed at most every 30 seconds. History is one bounded JSON file written every five minutes and on each status change. Probe parallelism is limited to eight and each probe times out after three seconds.

## Maintenance plans

A plan combines one action, a scope, one trigger and optional guards. Plans run only while **Scheduled maintenance** is on; **Run now** works either way and skips the guards.

### Actions

| Action | Kernel forward (nftables/iptables) | HAProxy | Realm | GRE, FRP, rathole |
| --- | --- | --- | --- | --- |
| **Soft refresh** (no disconnect) | Reapply owned rules from saved state; established flows keep their mappings | `systemctl reload` (graceful worker reload) | not applicable, skipped | not applicable, skipped |
| **Restart** (users reconnect) | Clear only this forward's tracked flows (see below) | `systemctl restart` | `systemctl restart` | `systemctl restart` of the owned unit |
| **Reboot server** | `systemctl reboot` | | | |

A kernel forward has no process to restart, and reapplying its rules does not affect existing flows. **Restart** therefore deletes the conntrack entries that this forward DNATed to its own targets: the original destination port (and address, unless the bind is a wildcard) plus each target as the reply source. For a kernel forward this has the same effect as a reboot. Other forwards, the host's own connections and the rest of the table are untouched, and the host table is never flushed. This needs the `conntrack` tool (package `conntrack`); without it, these steps fail with a clear message and the page warns in advance.

### Triggers

- **Every day** at 1–6 local times.
- **Every few hours** (1–168 h), counted from the previous run.
- **On weekdays** at chosen times.
- **After long uptime** (reboot only): checked at chosen times, runs when uptime exceeds 1–60 days.
- **When health fails**: a check of a scoped tunnel is down, or its latency stays above a limit, for 1–120 minutes. Only the affected tunnels are acted on. Requires health monitoring.

A scheduled run that starts more than ten minutes late, for example because the panel was stopped, is recorded as missed instead of running at an unexpected time.

### Guards

| Guard | Effect |
| --- | --- |
| Time window | Interval and health plans run only between two local times; windows may wrap past midnight |
| Quiet traffic | Wait until total host traffic is below a rate, for up to 360 minutes; then skip (default) or run |
| Cooldown | Minimum minutes between two runs of the plan |
| Runs per day | 1–48, counted per local day |
| Notice | A cancellable countdown, shown on the page, before the run starts |
| Pause between items | Seconds between tunnels, so not everything drops at once |
| Minimum uptime | Reboot loop guard: no automatic reboot this soon after boot (default 30 minutes) |
| Dry run | Records what would happen without doing it |

Saving an enabled reboot plan that is not a dry run requires a second confirmation. A reboot is recorded before `systemctl reboot` is called; after the next boot the record is completed with the boot time.

### Templates

**Nightly soft refresh**, **Nightly connection reset** (04:30, once traffic is below 20 Mbps), **Auto-heal outages** (down for 3 minutes), **Fix sustained high latency** (above 400 ms for 10 minutes between 02:00 and 07:00), **Weekly reboot** (Friday 04:30 with a 5-minute notice) and **Reboot after long uptime** (7 days). Every template can be edited before saving.

### History

Each step is recorded with its plan, trigger (schedule, health or manual), target, result (done, failed, skipped, dry run, cancelled, rebooting) and message. History keeps the newest 1,000 entries; the page shows the latest 300 and filters problems.

## Boundaries

- Every action uses an existing allowlisted operation: `systemctl reload|restart` on units that pass the managed-service check, the Bash API's `kernel-refresh` and `flows-reset ID`, or `systemctl reboot`. No command, path or unit name comes from the browser.
- Each step takes the broker's mutation lock only for its own command, so a staggered plan does not block other changes.
- Plan and setting changes are revision-checked. Background runs are audited by action name.
- Agent brokers have neither feature. Demo mode simulates probes and runs and labels every record.
- Health checks measure reachability from this server, not from clients or through the client's network. A destination that accepts TCP connections can still fail for VPN clients.

Local evidence: Go unit tests for the state machine, schedules, guards and reports; a namespace test that rule refresh keeps established flows and flow reset clears only the selected forward. Long-running behavior, real reboots and provider networks still need checks on real servers; see [Operations](OPERATIONS.md#deployment-checks-still-requiring-real-hosts).
