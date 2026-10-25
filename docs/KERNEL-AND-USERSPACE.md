# Kernel and userspace responsibilities

The useful distinction is where packets are processed. Every engine uses Linux sockets/drivers eventually; that does not make every forwarding engine a kernel dataplane. This inventory describes the implemented adapters, not every feature of upstream software.

| Component | Packet/data path | Management work |
| --- | --- | --- |
| GRE | Linux GRE interfaces encapsulate/decapsulate packets in the kernel. | Bash creates addresses, routes and interface settings; systemd restores them at boot. |
| nftables forwarding | Netfilter DNAT/SNAT, conntrack, distribution and TCP MSS rules execute in the kernel. No per-packet Bash/Go relay. | Bash validates state and submits owned atomic nft batches. |
| iptables forwarding | Netfilter NAT/filter/conntrack execute in the kernel. The installed iptables backend can use legacy xtables or nf_tables. | Bash builds scoped restore batches; iptables commands are userspace control tools. |
| HAProxy | A resident userspace process accepts and relays TCP connections; checks, affinity, PROXY metadata and TLS/SNI routing use HAProxy. | Bash renders managed configuration and systemd units; Go orchestrates approved operations. The adapter does not enable kernel forwarding or make a general zero-copy guarantee. |
| Realm | A resident userspace process relays TCP/UDP and handles implemented network options. | Bash renders TOML and service units. |
| FRP | Resident frpc/frps processes handle reverse connections, multiplexing and TCP/WS/QUIC/KCP transports. The WSS entrance additionally uses HAProxy. | Managed configuration/services, peer credentials and paired operation orchestration. |
| rathole | Resident userspace processes handle reverse TCP/UDP listeners and the adapter's Noise-over-TCP transport. | Managed configuration/services and peer credentials. |
| Per-port accounting | Named nftables counters count packets in input/output/forward hooks, including for userspace relay public ports. | The optional broker samples counters, keeps the bounded ledger/history and detects quota crossings. |
| GRE accounting | Kernel interface counters exposed through sysfs. | The optional broker reads deltas and maintains cycle baselines. GRE and port usage can overlap. |
| Automatic quota pause | Scoped nftables drops block both directions after a crossing is detected, including existing tracked flows. | Detection is periodic in the optional broker; it is not an in-kernel named quota or a byte-exact cutoff. See [Traffic accounting](TRAFFIC-ACCOUNTING.md). |
| Dashboard telemetry | Linux exports CPU, memory and network statistics through procfs. | Go computes deltas on demand; the visible browser polls and renders. No disk history or new collector. |
| Web panel and Agents | No VPN traffic is carried by the management channel. | HTTP/authentication, Node transport, jobs, validation, rendering, backups, encryption, audit and persistence remain in userspace. |

## Practical choices

Use nftables or iptables when plain forwarding and kernel distribution meet the requirement. Use GRE when an IP link is needed. Use HAProxy when TCP health checks, failover, affinity or TLS/SNI routing matter; use Realm for a simple resident TCP/UDP relay. Reverse engines solve reachability/transport requirements that NAT rules alone do not solve. There is no universal fastest engine across RTT, packet size, encryption and host limits.

Keeping optional collection/history off avoids their periodic work. Live dashboard readings only run on demand. Shifting validation, authentication or backup processing into the kernel would add complexity without removing the work actually needed for those tasks. No eBPF agent, flow offload or kernel module is added by this change.

## Verification scope

Local tests cover telemetry deltas/cache/reset behavior and scoped quota rules, including real established TCP blocking/resume inside a private Linux network namespace. Existing namespace checks cover forwarding, GRE and available relay engines. These do not replace checks on a disposable VPS for reboot ordering, distribution service policies, NIC offload, unusual routing or provider accounting.

## Upstream references

- [Linux procfs statistics](https://docs.kernel.org/filesystems/proc.html)
- [Netfilter nftables stateful objects](https://wiki.nftables.org/wiki-nftables/index.php/Stateful_objects)
- [Native nftables quotas](https://wiki.nftables.org/wiki-nftables/index.php/Quotas): a possible future byte-level guard, distinct from this release's sampled cycle policy.
