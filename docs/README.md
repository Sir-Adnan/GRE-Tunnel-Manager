# Developer Docs

Developer reference for the modular v1 Bash manager. User-facing docs are in the Persian [root README](../README.md); repository conventions live in [CLAUDE.md](../CLAUDE.md).

| Doc | Read it when you need... |
| --- | --- |
| [ARCHITECTURE.md](ARCHITECTURE.md) | script layout, control flow, naming/addressing scheme, design decisions |
| [ARTIFACTS.md](ARTIFACTS.md) | every file/service/iptables rule created on servers + reboot/cleanup behavior |
| [DEVELOPMENT.md](DEVELOPMENT.md) | golden rules, bash conventions, testing, release checklist, known pitfalls |
| [OPERATIONS.md](OPERATIONS.md) | read-only CLI, preflight, restore/recovery, GRE removal and rollout |
| [PERFORMANCE.md](PERFORMANCE.md) | High-Load design (RPS/conntrack/NOTRACK), sizing math, 64k NAT ceiling, non-goals |
| [CHANGELOG.md](CHANGELOG.md) | modular v1 releases and historical v13.x releases |
| [REVIEW-ROADMAP.md](REVIEW-ROADMAP.md) | current findings, Kariz/rathole comparison, prioritized methods and acceptance gates |
| [HAPROXY.md](HAPROXY.md) | TCP settings, state v2, restricted stats, worker reload, limitations and next features |
| [TUNING-CLEANUP.md](TUNING-CLEANUP.md) | closed legacy cleanup, global tuning journal, drift-aware restore and historical migration |
