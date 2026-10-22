# Performance and capacity

The Bash manager configures the control plane; packets run in the kernel or selected relay. Switching manager language does not accelerate packets. No continuous menu probing is used. Optional services have real, nonzero CPU/RAM costs.

| Engine | Scope | Tradeoff |
| --- | --- | --- |
| Routing | L3 forwarding | Requires return-path control |
| iptables/nftables | Kernel TCP/UDP NAT | conntrack/tuple limits; these presets have no health checks |
| Realm | TCP/UDP relay | Outgoing sockets, UDP association lifetime, service resources |
| HAProxy | TCP relay | Checked load balancing; no generic UDP in this adapter |
| FRP | Reverse connections | Processes on both sides; transport/mux overhead |
| rathole | Noise reverse TCP/UDP services | Processes on both sides; this preset carries UDP over TCP |
| WSS | TLS gateway + FRP | Extra HAProxy service and certificate lifecycle |

iptables and nftables share connection-tracking/NAT infrastructure. Neither is universally fastest. Rule shape, packet size, flow churn, NIC offload, CPU topology and kernel matter. Transactional configuration improves manageability; speed requires measurement.

## NAT capacity

SNAT capacity depends on translated tuples for a protocol/source address/final destination. Several entrance ports mapped to the SAME final IP/port do not create independent pools. Actual destination ports/IPs, extra source addresses or routed topology may change capacity. Widening `ip_local_port_range` alone does not expand kernel NAT allocation.

Connections are not users. Conntrack entry RAM varies with kernel/extensions/accounting. Old fixed estimates and 100k-user statements were not backed by reproducible benchmarks.

## Explicit global tuning

Performance menu 14 now exposes opt-in capacity and local-TCP profiles with a durable before/applied journal. Restore writes the captured baseline only while the current setting still matches what the manager applied; later administrator changes are preserved. No automatic GRE TCP/conntrack/IPv6 tuning, new RPS/NOTRACK helper or guessed default rollback is performed. Historical installs have no trustworthy before-values: retire recognized persistence, retain unknown runtime values and review separately. See [TUNING-CLEANUP.md](TUNING-CLEANUP.md).

RPS can add inter-processor overhead; all-core masks are not universally optimal. New capacity presets deliberately avoid changing conntrack hash size or shortening existing idle timeouts. Raising a limit is not a RAM allocation forecast or a user-capacity guarantee.

Host TCP congestion control affects locally terminated connections such as relays, not the remote endpoints' congestion control of forwarded TCP. MSS clamping uses known route MTU, not omniscient discovery of a blackholed underlay PMTU.

The native nftables adapter now clamps owned TCP SYN MSS using `rt mtu`, which exposes route MSS to this expression. A packet test verifies MTU 1430 yields MSS 1390 and preserves a smaller peer MSS. Only original-direction owned DNAT flows are matched. UDP has no MSS; large UDP payloads still need a suitable path MTU. See the kernel's [MSS setter](https://github.com/torvalds/linux/blob/master/net/netfilter/nft_exthdr.c) for the no-increase behavior.

Rathole's [upstream benchmark](https://github.com/rathole-org/rathole/blob/main/docs/benchmark.md) is not a capacity promise for an Internet path. Its Noise transport runs over TCP here; UDP datagrams inherit TCP ordering/retransmission delays under loss. Compare against native UDP/GRE and FRP QUIC on the actual route before choosing a transport.

## Measurements

Record hardware/kernel/backend versions, topology, MTU, RTT/loss, packet sizes, flow count/churn, offload state, p50/p95/p99 latency/jitter, throughput, packets/s, softirq, drops, conntrack, memory and service CPU. Test updates under traffic and target failure/recovery. Avoid zero-cost or universal performance claims.

HAProxy per-connection settings avoid requiring global tuning for every relay. Maxconn/per-target caps, queue waits, health frequency, logs and idle timeout each have resource/behavior tradeoffs. Errors-only logging can reduce journal volume; longer idle timeouts retain idle sessions longer. Worker reloads allow old sessions to drain but can temporarily keep old workers/RAM alive. See [HAPROXY.md](HAPROXY.md) for limits and restart cases.
