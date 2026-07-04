# Performance & High-Load Design

Target: 10k-100k+ concurrent users through one Iran relay box, while the manager itself stays at ~0% CPU/RAM. Everything here is kernel-side and opt-in via menu 14.

## Baseline costs (no profile)

| Component | CPU | RAM |
| --- | --- | --- |
| gre.sh menu process | 0 when closed | ~4 MB while open |
| Watchdog (per tunnel) | ~0% (1 ping fork / 10 s) | ~2 MB |
| GRE data plane | kernel softirq; no crypto; ~ a few % per 100 Mbit/core | KB-scale |
| Realm (optional) | epoll-based, efficient | 5-15 MB idle |

Intrinsic GRE overhead: 28 B/packet (v4+key) ⇒ ~4-5% throughput at MTU 1430; latency impact ≈ 0.

## The three bottlenecks at scale (and what menu 14 does)

1. **Single-core softirq.** NIC RSS hashes only the OUTER GRE header (fixed src/dst, no ports) ⇒ the whole tunnel lands on one core (~1-3 Gbps ceiling). Fix: **RPS/RFS** — `gre_perf.sh` writes an all-cores mask (capped at 32) to every `gre*` rx queue + `rps_sock_flow_entries=32768`, `rps_flow_cnt=4096`. Inner flows spread across cores. Applied at boot (gre-perf.service) and after each new tunnel creation.
2. **conntrack table.** Default max (~65k; base install raises to 262144 via FW_SCRIPT) is too small: users × connections easily exceeds it, and full table = dropped new connections. Profile tiers:
   - HIGH: max 524288, buckets 131072 — worst-case ~180 MB RAM, needs 1 GB+
   - EXTREME: max 1048576, buckets 262144 — worst-case ~400 MB RAM, needs 2 GB+
   Entries cost ~320 B and exist ONLY per live connection (RAM grows with real load, not upfront; buckets are ~1-2 MB fixed). `tcp_timeout_established` cut from 5 days to 2 h, `time_wait`/`fin_wait` to 30 s — dead flows leave fast. `hashsize` also written via module param for kernels with read-only buckets sysctl. `modules-load.d` entry guarantees the sysctls apply at boot.
3. **Per-packet conntrack cost of the carrier.** Outer proto-47 packets don't need tracking (inner traffic still fully tracked for NAT). `raw PREROUTING/OUTPUT -p gre -j NOTRACK` (v4+v6) removes one lookup per packet. Safe because our GRE INPUT accept is stateless.

Plus in the profile sysctls: full ephemeral port range (1024-65535), `somaxconn=65535`, `netdev_max_backlog=16384`, `tcp_max_syn_backlog=8192`, `tcp_slow_start_after_idle=0`, `tcp_mtu_probing=1`.

## The ~64k NAT ceiling (cannot be sysctl'd away)

MASQUERADE/SNAT gives ~64k concurrent connections per (protocol, source IP, dest IP, dest port). One forwarded port to one kharej service caps around 64k concurrent flows. Operational fix, documented in the in-script Scaling Guide: forward 2-4 different ports (menu 9) to the same service and split users between them in the panel — each (dest port) is an independent 64k pool. A code-level fix (multi-IP SNAT pools) would require widening the inner /30 subnet and breaks the compatibility contract — rejected.

## MTU / MSS

- Default 1430 everywhere (compat). Optional per-tunnel: up to 1472 (gre+key/v4) or 1452 (ip6gre+key).
- MSS clamp-to-pmtu on FORWARD (base, since v13.8) makes TCP safe even with filtered ICMP or a too-high MTU choice; `tcp_mtu_probing=1` (profile) covers locally-originated flows.

## Non-goals (deliberate)

- **No metrics/monitoring daemon** — would violate zero-footprint. Status is read on demand from /proc (perf_show_status).
- **No encrypted backend by default** — per-packet crypto is real CPU at 100k users; GRE stays plain kernel encap. If ever added (e.g. WireGuard), it must be a separate opt-in path, never the default.
- **No systemd-timer watchdogs** — the sleeping bash loop is cheaper than periodic unit activation.

## Verification commands (on server)

```bash
cat /proc/sys/net/netfilter/nf_conntrack_count   # live connections
cat /proc/sys/net/netfilter/nf_conntrack_max     # tier value if profile active
cat /sys/class/net/gre*/queues/rx-0/rps_cpus     # non-zero mask = RPS on
iptables -t raw -S | grep NOTRACK                # NOTRACK present
sysctl net.ipv4.tcp_congestion_control           # bbr
```
