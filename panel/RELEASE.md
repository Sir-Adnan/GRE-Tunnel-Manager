# GRE Tunnel Manager v1.3.7

The panel gains optional health monitoring and scheduled maintenance. Both are off after installing or upgrading, and do no background work while off.

## Health

- **Health** checks every enabled destination on an interval (default 30 s): one TCP connection closed before any data, or a ping for UDP-only services. It also pings GRE peers over the tunnel and reads managed service states.
- It shows status, latency, 24 h / 7 d / 30 d uptime with hourly and daily cells, an outage history and a weekly report with downtime, latency, jitter, server load, maintenance runs and accounted traffic. The report exports as CSV and prints.
- **Health → Server** shows conntrack usage, hash size, the idle-TCP timeout and drops, plus CPU steal, softirq and I/O wait. Ping and jitter that rise over hours and clear after a reboot usually come from a filling conntrack table; the page names the cause and points to [ServerTools](https://github.com/Sir-Adnan/server-tools) for tuning. The panel changes no kernel setting.

## Maintenance

- Plans run a **soft refresh** (reapply kernel rules, reload HAProxy gracefully; nobody is disconnected), a **restart** (services, GRE links, reverse tunnels) or a **server reboot**.
- A restart of an nftables/iptables forward clears only that forward's tracked flows, which for it has the same effect as a reboot. The conntrack table is never flushed. This needs the `conntrack` package.
- Triggers: daily, on weekdays, every N hours, after long uptime, or when a tunnel is down or slow for N minutes (only affected tunnels are acted on).
- Guards: time window, wait for quiet traffic, cooldown, daily limit, cancellable notice, pause between tunnels, a reboot loop guard and dry run. Six templates are included. Saving an enabled reboot plan asks twice.

## Other changes

- Dashboard live activity refreshes every 2 s by default; 1, 2, 5 or 15 s can be chosen and is remembered in the browser.

## Upgrade and verification

Run the current panel installer to install the matching v1.3.7 package, then refresh the browser. Downloading the script alone does not upgrade the executable. Existing credentials, certificates and managed tunnel settings are kept. Use matching Controller/Agent packages when upgrading Nodes. Install `conntrack` (`apt install conntrack`) if you plan restart plans for kernel forwards.

Linux amd64/arm64 archives contain the executable, embedded frontend, matching Bash helper and dependency notices. Verify `SHA256SUMS`. Managed servers do not need Node.js, Python or a compiler.

Tested with unit tests and in isolated Linux network namespaces, including a check that rule refresh keeps established flows and flow reset clears only the selected forward. Long-running behavior and real reboots have not yet been verified on a server.
