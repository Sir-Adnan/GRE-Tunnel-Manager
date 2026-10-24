# Project review and next steps — 2026-10-21

> Historical implementation review. Describes its recorded milestone, not current installation instructions. Start with the [current guides](../README.md).

This source/configuration review was started with v1.1.0 and updated for v1.2.0. It is not a production two-VPS benchmark. The generated release, Bash modules, build/tests, CI and operational docs were examined. No live server was deployed or remotely changed.

## Recommendation: keep Bash, refactor incrementally

Keep Bash as the control plane. Linux routing/NAT and selected relay binaries process traffic; rewriting menus in another language does not make the data plane faster. Modular sources, validated state, owned resources and reproducible builds are a useful base. A complete rewrite would also have to reproduce GRE wire compatibility and migrate legacy installations.

Continue moving legacy capabilities behind explicit adapters. If a web/API control plane is later required, keep the backend contracts and render/apply model; do not grow a shell HTTP server or make a permanent agent mandatory for kernel-only forwarding.

## Findings and work completed

| Area | Finding / action in this release |
| --- | --- |
| State loading | Unreadable state previously looked empty. Reject nonregular/unreadable/dangling files and explicit missing files; only an absent default state means a new install. |
| nftables / GRE MTU | Add scoped route-MSS clamping. Actual SYN capture verifies 1390 at GRE MTU 1430 and preservation of a smaller 1200 MSS. This is not a universal PMTU cure. |
| Reverse listener conflicts | A socket-only check misses DNAT. New FRP/rathole entrances check local IPs, current sockets, managed TSV and recognized legacy listeners under the shared lock. Unknown manual rules still require inspection. |
| Reverse method UX | Separate engine selection from transport choice. Add rathole with authenticated Noise NK; add an offline method guide. |
| Optional binary contract | Official rathole version output is a multiline build report; validate the real archive behavior rather than assume a short semantic-version line. |
| Failure cleanup | New rathole startup failure removes the new owned instance only if stopping succeeds; existing names/binaries are retained. |
| Operational claims | Tests and docs distinguish configured/running/connected, local checks and actual two-server readiness. No capacity or latency guarantee. |

## Remaining gaps, in priority order

| Priority | Gap / evidence | Proposed change and acceptance criteria |
| --- | --- | --- |
| P1 | Real reboot/systemd/UFW/Docker/provider behavior is untested. Namespace tests cannot establish this. | Two disposable VPSs; reboot each peer independently under TCP/UDP traffic, exercise firewall reloads, boot order, unavailable peer and rollback. Record kernel/backend versions and logs. |
| P1, partially resolved | v1.2.0 removes implicit TCP/conntrack/IPv6 tuning and guessed restoration; explicit journaled profiles preserve later administrator changes. Shared `fix_firewall` policy and historical runtime RPS/NOTRACK remain outside this ownership model. | Keep remaining global firewall changes separate; introduce peer-scoped policy with an explicit migration/preview. Do not infer historical administrator values. |
| P1, cleanup redesigned | v1.2.0 replaces bulk wipe with closed inventory/backup/checked deletion, protects Simple GRE peer/dependencies and refuses unknown commands/custom units. Interrupted multi-resource deletion still is not atomic. | Exercise target-host service ordering/interruption/recovery; retain manual rules and backups. Add structured ownership for future links before automating richer topology removal. |
| P1 | Legacy Realm updater/installer still uses a mutable latest-release path; modern Realm/FRP/rathole installers are pinned. The shortcut only syntax-checks a mutable script download. | Make all update paths explicit, pinned and verifiable, with version preview and retained previous artifact. Avoid claiming that a syntax check authenticates a download. |
| P2 | FRP/rathole are separate service/config namespaces, outside forwarding snapshots and GRE dependency checks. | Versioned reverse-connection data, shared create/edit/disable/restore lifecycle, secret references and explicit schema migration. Never put private keys in a topology-only export. |
| P2 | Preflight cannot prove reachability/return routing; disabled/restored relay conflicts with unmanaged listeners may be caught only on startup. | Optional on-demand connection probes with timeouts and clear configured/running/reachable labels; never enable continuous probing or consume service data silently. Model managed active listeners when checking ownership. |
| P2 | Only default GRE address/interface references are guarded. Custom routes, FRP/rathole endpoints and multi-hop loops are outside the model. | Build a resource dependency graph from structured records; show affected connections before removal. Verify cycles/route ambiguity with bounded, deterministic checks. |
| P2 | Backend capability/installer/menu branches are repeated across modules. | A small Bash capability registry and adapter contract; keep version-specific rendering/tests local. Avoid dynamic eval or plugin sourcing from user-writable directories. |
| P2 | No reproducible Internet workload benchmark; no kernel health-checked failover. | Opt-in benchmark profiles for TCP throughput, UDP loss/jitter, flow churn and failure recovery. Use HAProxy for current checked TCP balancing. A health-checked kernel controller would require an explicitly selected process/timer. |
| P3 | Restore points have no retention policy; richer support export is absent. | User-selected retention with a delete preview; redacted export that excludes tokens/private keys and checks certificate permissions. |

## Kariz and rathole

Kariz advertises direct/reverse connections, multiple transports and an agent/panel workflow. Those are useful product-level comparison points; its throughput/RAM claims have not been reproduced here. Its current [license](https://github.com/Erfan-XRay/Kariz/blob/main/LICENSE) explicitly restricts copying/derivation and managing its core from other software. No Kariz code, configuration format, protocol or managed adapter is included. Any later integration needs separate permission from its author. See its [README](https://github.com/Erfan-XRay/Kariz/blob/main/README.md) for its own feature descriptions.

Rathole has an [Apache-2.0 license](https://github.com/rathole-org/rathole/blob/main/LICENSE) and documented TCP/UDP reverse services. This release's independently written adapter targets the actual [0.5.0 release](https://github.com/rathole-org/rathole/releases/tag/v0.5.0), rather than every feature on main. The [Noise documentation](https://github.com/rathole-org/rathole/blob/main/docs/transport.md) specifies server private-key authentication and client public-key verification with NK. We exercise valid keys and a wrong-key rejection. Its [README](https://github.com/rathole-org/rathole/blob/main/README.md) also cautions that CPU-bound local benchmarks do not imply the same gains over a constrained Internet path.

## Additional methods worth adding

These are recommendations for future adapters, not claims of already implemented features. Prefer a small number of well-tested methods over a long menu of incompatible configurations.

| Priority | Method | Suitable use / tradeoff |
| --- | --- | --- |
| Next | WireGuard server links | Encrypted routed links with kernel processing on supported Linux systems; then reuse existing NAT/relay adapters over private addresses. Need key rotation, AllowedIPs/route conflict checks, non-default routes and reboot tests. [Official setup](https://www.wireguard.com/quickstart/) |
| Next, after WireGuard | AmneziaWG link profiles | Keep a distinct version/capability adapter; do not treat its keys/options/build requirements as automatically identical to every WireGuard implementation. Existing UDP service forwarding already works. |
| Later | GOST relay chains | Proxy chaining and independently selectable data channels; useful for multi-hop or an upstream proxy. Needs strict authentication/TLS verification and bounded chain depth. Overlaps FRP for simple reverse ports, so add it for a concrete chain scenario. [Official model](https://www.gost.run/en/concepts/proxy/) |
| Later / specialist | GRE-over-UDP with FoU/GUE | A possible alternative when native GRE protocol is unavailable but UDP works. Verify kernel/iproute2 support, encapsulation, firewall, checksums, NAT behavior and actual MTU on both ends. It does not add encryption by itself. [iproute2 link reference](https://github.com/iproute2/iproute2/blob/main/man/man8/ip-link.8.in) |
| Specialist | IPVS with explicit health controller | Kernel L4 distribution for larger multi-destination deployments; routing/DR/NAT and health-controller lifecycle are additional design work. A controller is an optional resident service, not free health checking. [Kernel reference](https://www.kernel.org/doc/html/latest/networking/ipvs-sysctl.html) |
| Scenario-specific | KCP/FEC or other UDP transports | Consider only after measured loss demonstrates a need. Retransmission/FEC/duplication can consume extra CPU/bandwidth; do not label it universally faster or lower-ping. Native UDP/GRE and existing FRP QUIC are comparison baselines. |

Do not prioritize VXLAN/GRETAP unless an actual Layer-2 requirement appears; they add bridge/broadcast and MTU considerations to an L3/service-forwarding product. HTTP CONNECT tcpmux needs its own explicitly documented protocol adapter; FRP stream mux already present is a different feature.

## GRE-specific improvements

Preserve the current keys, IDs, addresses and MTU defaults. Add an opt-in underlay/overlay diagnostic showing route MTU, overhead budget, ICMP delivery and both peers' settings; never blindly raise MTU after a successful small ping. Add peer-scoped firewall rules as an explicit migration, with a preview of existing broad legacy rules. Add structured route ownership and exact removal before advertising safe multi-hop topology editing. For confidentiality use an encrypted link/transport; GRE itself provides no encryption. Native nftables MSS clamping is implemented now; underlay PMTU discovery and automated route migration remain future work.

## Validation performed

Pure Bash/config regression tests, deterministic rebuild and ShellCheck cover the modern modules. Private Linux namespaces exercise real TCP/UDP NAT, keyed GRE, MSS capture, HAProxy failover, Realm, FRP TCP/WS/WSS/QUIC and installed rathole Noise. Optional engines absent from CI can be skipped; they were exercised locally with the pinned binaries. No production reboot, multi-VPS path, sustained-loss benchmark or exact administrator-firewall restoration is claimed.

v1.2.0 additionally tests actual HAProxy worker reload with a retained TCP session, PROXY v1/v2 client metadata, real duplicate-rule/Simple GRE cleanup preserving unrelated rules, and mocked sysctl failure/drift restoration. Detailed HAProxy features and next steps are in [HAPROXY.md](../HAPROXY.md).
