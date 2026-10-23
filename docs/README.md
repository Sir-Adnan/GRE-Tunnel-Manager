# Documentation

Start with the [README](../README.md), then the guides below. Technical guides are written in English, with an additional [Persian quick-start README](../README.fa.md); the web interface supports Persian and English. Technical references cover the modular v1 Bash manager. [AGENTS.md](../AGENTS.md) is the canonical agent instruction source; CLAUDE.md only points to it.

| Doc | Read it when you need... |
| --- | --- |
| [PHASE-7-REVIEW.md](PHASE-7-REVIEW.md) | v1.3.1 alignment, configuration/profile workflows and verification limits |
| [CONFIGURATION-EDITOR.md](CONFIGURATION-EDITOR.md) | Native previews, managed edits, review/apply and ownership limits |
| [CONNECTION-PROFILES.md](CONNECTION-PROFILES.md) | VPN-oriented starting profiles and real engine tradeoffs |
| [ROADMAP.md](ROADMAP.md) | Phase-gated UI, installation, Node/Agent and engine-capability development |
| [PHASE-6-REVIEW.md](PHASE-6-REVIEW.md) | Remote summaries, compact dashboard, verification and remaining scope |
| [REMOTE-TRAFFIC.md](REMOTE-TRAFFIC.md) | Optional Agent snapshots, local enable/pause, compatibility and privacy |
| [TRAFFIC-ACCOUNTING.md](TRAFFIC-ACCOUNTING.md) | Customer/port usage, cycle reset, advisory quotas, retention, CSV and limits |
| [HAPROXY-ROUTING.md](HAPROXY-ROUTING.md) | Closed SNI/HTTP routing, HTTPS PEM ownership and v4 compatibility |
| [REALM-PROFILES.md](REALM-PROFILES.md) | Pinned WS/MPTCP/IPv6-only profiles and kernel/feature checks |
| [PHASE-5BCD-REVIEW.md](PHASE-5BCD-REVIEW.md) | Delivered advanced management, verification and release boundaries |
| [ENGINE-CAPABILITIES.md](ENGINE-CAPABILITIES.md) | Adapter/version matrix, installed-version discovery and compatibility labels |
| [PANEL-REMOVAL.md](PANEL-REMOVAL.md) | Confirmed panel-only removal, retained tunnels, identity loss and recovery guards |
| [PHASE-5A-REVIEW.md](PHASE-5A-REVIEW.md) | Engine foundation, HTTP readiness, Realm correction and removal verification |
| [PHASE-1-REVIEW.md](PHASE-1-REVIEW.md) | Completed interface corrections, validation evidence and remaining boundaries |
| [PHASE-2-REVIEW.md](PHASE-2-REVIEW.md) | Quick/custom installation, HTTP/HTTPS, credential preservation and validation boundaries |
| [USER-GUIDE.md](USER-GUIDE.md) | Usage reference, engine selection, GRE, reverse setup and operational limits |
| [TERMINAL-UI.md](TERMINAL-UI.md) | Terminal setup, staged forms, dedicated managers and fixed-color troubleshooting |
| [WEB-PANEL.md](WEB-PANEL.md) | Optional Go panel installation, HTTP/HTTPS, supported adapters, metrics, architecture and limits |
| [ARCHITECTURE.md](ARCHITECTURE.md) | script layout, control flow, naming/addressing scheme, design decisions |
| [ARTIFACTS.md](ARTIFACTS.md) | every file/service/iptables rule created on servers + reboot/cleanup behavior |
| [DEVELOPMENT.md](DEVELOPMENT.md) | golden rules, bash conventions, testing, release checklist, known pitfalls |
| [OPERATIONS.md](OPERATIONS.md) | read-only CLI, preflight, restore/recovery, GRE removal and rollout |
| [PERFORMANCE.md](PERFORMANCE.md) | High-Load design (RPS/conntrack/NOTRACK), sizing math, 64k NAT ceiling, non-goals |
| [CHANGELOG.md](CHANGELOG.md) | modular v1 releases and historical v13.x releases |
| [REVIEW-ROADMAP.md](REVIEW-ROADMAP.md) | current findings, Kariz/rathole comparison, prioritized methods and acceptance gates |
| [HAPROXY.md](HAPROXY.md) | TCP settings, state v2, restricted stats, worker reload, limitations and next features |
| [TUNING-CLEANUP.md](TUNING-CLEANUP.md) | closed legacy cleanup, global tuning journal, drift-aware restore and historical migration |

The current phase-gated development plan is tracked in [ROADMAP.md](ROADMAP.md).

- [Nodes and Agents](NODES.md): optional secure read-only inventory, installation and recovery.
- [Phase 3 review](PHASE-3-REVIEW.md): delivered scope and verification evidence.

- [Paired connections](PAIRED-CONNECTIONS.md): explicit remote-operation opt-in, coordinated GRE/FRP, leases and recovery.
- [Phase 4 review](PHASE-4-REVIEW.md): delivered operation scope, verification and rollout limits.
