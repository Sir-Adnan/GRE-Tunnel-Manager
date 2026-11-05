# Documentation

Start with the project quick start in [English](../README.md) or [Persian](../README.fa.md). These technical guides are maintained in English.

## Setup and daily use

| Guide | What it covers |
| --- | --- |
| [User guide](USER-GUIDE.md) | Choosing a method, creating connections and everyday actions |
| [Web panel](WEB-PANEL.md) | Installation, HTTP/HTTPS, upgrades and access recovery |
| [Nodes and Agents](NODES.md) | Local-only operation, Controller setup and enrollment |
| [Connect two servers](PAIRED-CONNECTIONS.md) | Coordinated GRE/FRP setup and failure recovery |
| [Operations](OPERATIONS.md) | Validation, backups, restoration and deployment checks |
| [Backup and restore](BACKUP-RESTORE.md) | Encrypted portable recovery, fresh-server migration and optional accounting |
| [Panel removal](PANEL-REMOVAL.md) | Removing the panel while retaining tunnels |

## Connections and traffic

| Guide | What it covers |
| --- | --- |
| [Setup presets](CONNECTION-PROFILES.md) | Three starting presets per engine and their tradeoffs |
| [Engine capabilities](ENGINE-CAPABILITIES.md) | Supported versions, adapter scope and validation |
| [Engine maintenance](ENGINE-MAINTENANCE.md) | Manual official version checks, verified updates and binary recovery |
| [HAProxy](HAPROXY.md) · [Routing](HAPROXY-ROUTING.md) | TCP settings, affinity, checks, TLS/SNI/HTTP |
| [Realm profiles](REALM-PROFILES.md) | WS, MPTCP and IPv6-only options |
| [Configuration editor](CONFIGURATION-EDITOR.md) | Inspection, supported edits and review/apply |
| [Traffic accounting](TRAFFIC-ACCOUNTING.md) · [Remote summaries](REMOTE-TRAFFIC.md) | Collection, resets, quotas, history and Node reports |
| [Health and maintenance](HEALTH-AND-MAINTENANCE.md) | Uptime, outages, weekly reports, conntrack pressure and scheduled refresh/restart/reboot |
| [Performance](PERFORMANCE.md) · [Server optimization](OPTIMIZATION.md) | Capacity limits and opt-in, reversible kernel settings |
| [Port ranges, domains and DNS](PORTS-AND-DNS.md) | Kernel port ranges and mapping, domain destinations with refresh, the server's DNS, and importing from Port Forward Manager |
| [Monitoring](MONITORING.md) | Notifications (webhook, Telegram), diagnosis, GRE quality and speed tests, far-side checks and Prometheus metrics |
| [Retiring old installations](RETIRING-OLD-INSTALLS.md) | Removing v13.x forwards, Simple GRE and old tuning files |

## Development and reference

[Architecture](ARCHITECTURE.md) · [Server artifacts](ARTIFACTS.md) · [Development](DEVELOPMENT.md) · [Interface conventions](INTERFACE.md) · [Terminal interface](TERMINAL-UI.md) · [Releasing](RELEASING.md)

[Changelog](CHANGELOG.md) records shipped changes. [Roadmap](ROADMAP.md) separates current scope from proposed work. Earlier implementation reports live in the [review archive](archive/README.md); they are historical evidence, not installation instructions.

- [Kernel and userspace](KERNEL-AND-USERSPACE.md): packet paths, accounting, quotas and lightweight dashboard telemetry.
