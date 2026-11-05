# GRE Tunnel Manager v1.4.1

Know when something breaks, why, and how good a tunnel is — and undo a change in one click. Everything new is off or on demand until you turn it on.

## Notifications

- A **notification center** behind the bell in the header: outages and recoveries, failover changes, automatic undo, maintenance results and scheduled backups, grouped by day, with unread counts. Selecting an event opens its page.
- **Settings → Notification channels** sends selected events to a **webhook** (JSON for n8n, Discord, Slack or your own service, optionally signed with HMAC-SHA256) and a **Telegram bot** (optionally through your own Bot API relay), in English or Persian. Three attempts per message, at most 20 messages per 10 minutes, and a test button. Secrets are stored root-only and never shown again.

## Change history and backups

- **Change history** shows every forwarding change as a timeline: which connections were added, removed or changed. **Restore to before this** reviews what restoring changes now and applies it; the current state is saved first, so a restore can itself be undone.
- **Backups → Schedule** saves recovery snapshots on the server daily or weekly, keeps the newest 1–60, and downloads any of them as a password-protected `.gtm-backup`.

## Diagnosis and tunnel tests

- **Diagnose** (Health details and the connection or GRE menus) answers "why isn't it working?" with a read-only checklist — forwarding, rules, services, ports, routes, connection-table pressure, GRE firewall policy, reachability — problems first, each with a fix.
- **Quality test** for GRE: 20 pings through the tunnel with latency, jitter and loss.
- **Through Nodes:** v1.4.1 Agents report their load and whether each GRE peer answers from their side. Health shows "Far side ✓/✗" beside local tunnels, so one-way blocks stand out, and Node details offer a **speed test** through the tunnel in both directions.
- **Metrics export:** an opt-in Prometheus `/metrics` endpoint with a bearer token shown once.

## Optimization

- A redesigned page: one control center with progress, the profile (a three-stop intensity and goal cards), server facts and **Apply all**, which reviews and applies every group with changes at once.
- **Profiles:** Conservative, Balanced or Aggressive for general use, many users or low latency. Balanced · General equals v1.4.0. Moving between profiles never goes below the server's original values; Aggressive is capped on servers under 2 GB.
- **Custom values** within safe bounds, with a confirmation for anything worse than the original.
- **Network card:** packet steering (RPS) across every CPU for single-queue virtual cards and a longer transmit queue, replayed at boot by a small unit.
- **Automatic undo:** watch tunnel health for 5–60 minutes after an apply and undo the step if a healthy connection goes down.

See [Monitoring](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/MONITORING.md) and [Server optimization](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/OPTIMIZATION.md).

## Upgrade and verification

Run the current panel installer to install the matching v1.4.1 package, then refresh the browser. Existing credentials, certificates and managed tunnel settings are kept. Upgrade Agents to v1.4.1 for far-side checks and speed tests; older Agents keep working without them.

Linux amd64/arm64 archives contain the executable, embedded frontend, matching Bash helper and dependency notices. Verify `SHA256SUMS`. Managed servers do not need Node.js, Python or a compiler.

Checked locally with Python, Go (race, vet) and frontend tests, ShellCheck and browser checks in both languages on desktop and phone. Not yet checked on real servers: boot replay of network-card settings, speed tests between two VPSs, far-side checks through real firewalls and delivery to real webhook and Telegram endpoints.
