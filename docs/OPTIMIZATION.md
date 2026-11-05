# Server optimization

The panel's **Optimization** page (terminal: **Tools → Server optimization**) offers server-wide kernel settings for tunnel and forwarding servers in four opt-in groups. Nothing changes until a group is reviewed and applied. Every change is journaled, can be undone step by step, and **Reset everything** returns each setting to its original value and deletes the panel's files.

This module replaces the tuning menu of v1.3.7 and earlier; its values and method were not carried over. Settings applied with that menu are imported on the first change (see [Upgrading](#upgrading-from-v137)).

## Never worse than the server's own values

Every recommendation is computed against the live value first, so a value the server already has, whether an administrator set it or the provider's image ships it, is never made worse:

| Mode | Rule |
| --- | --- |
| raise | Limits, queues and buffers only grow |
| lower | Timeouts only shrink |
| raise3 | `min default max` triples (`tcp_rmem`, `tcp_wmem`): each field only grows |
| prefer | The live value stays when it is an equivalent choice (`fq`, `cake` or `fq_pie`; `bbr`, `bbr2` or `bbr3`) |
| loose | Reverse-path filter: strict (1) becomes loose (2); off (0) and loose stay |

The page marks such a key **Server value is better; kept** and leaves it alone; only real improvements count as changes. A key the kernel does not have, or BBR when the kernel cannot load it, is skipped and shown as such.

The page also marks groups that **fit this server**: Connection tracking when kernel forwards exist, Relay TCP when HAProxy, Realm, FRP or rathole run, Tunnels & routing with GRE or more than one IPv4 address, and Packet queues when 20,000 or more connections are tracked. **Review recommendations** opens one review for every fitting group that still has changes.

## Groups and values

### Connection tracking (recommended for forwarders)

Fixes ping and jitter that rise over hours and clear after a reboot: the kernel keeps idle TCP entries for five days by default, abandoned VPN connections fill the table, and lookups slow down when the limit is far above the hash size.

| Key | Value | Mode | Why |
| --- | --- | --- | --- |
| `nf_conntrack_max` | 8 % of memory at ~350 B per flow, as a power of two (131072–4194304) | raise | Room for every user's connections |
| `nf_conntrack_buckets` | half the limit (≤ 2097152) | raise | Short lookups when the table is full |
| `nf_conntrack_tcp_timeout_established` | 3600 s | lower | Abandoned connections expire in an hour |
| `nf_conntrack_tcp_timeout_time_wait` / `fin_wait` / `close_wait` | 30 s | lower | Closing connections are freed quickly |
| `nf_conntrack_udp_timeout` | 60 s | raise | One-way UDP mappings last a little longer |
| `nf_conntrack_udp_timeout_stream` | 180 s | raise | WireGuard and QUIC sessions stay mapped |

A 1 GiB server gets 131072 flows (about 44 MiB if completely full; entries use memory only while connections exist), 4 GiB gets 524288. The limit is never set below the flows tracked right now.

An established TCP connection idle for more than an hour loses its tracking entry; its next packet starts a new flow, which can break a connection that is silent for longer than that. The **Relay TCP** group sets keepalives to 10 minutes for connections the server makes itself; VPN clients normally send their own keepalives well within an hour.

### Packet queues

| Key | Value | Mode |
| --- | --- | --- |
| `net.core.netdev_max_backlog` | 16384 | raise |
| `net.core.netdev_budget` / `netdev_budget_usecs` | 600 / 8000 | raise |
| `net.core.somaxconn` | 8192 | raise |
| `net.ipv4.tcp_max_syn_backlog` | 8192 | raise |

For busy servers: more packets per softirq pass and per-core queueing before drops, and longer accept/SYN queues for relay listeners.

### Relay TCP

For connections the server terminates or originates itself (HAProxy, Realm, FRP, rathole). Kernel forwards do not use these.

| Key | Value | Mode |
| --- | --- | --- |
| `net.core.default_qdisc` | `fq` (keeps `cake`, `fq_pie`) | prefer |
| `net.ipv4.tcp_congestion_control` | `bbr` (keeps `bbr2`/`bbr3`; only when available, `tcp_bbr` is loaded if needed) | prefer |
| `net.core.rmem_max` / `wmem_max` | 32 MiB | raise |
| `net.ipv4.tcp_rmem` / `tcp_wmem` | `4096 131072 33554432` / `4096 65536 33554432` | raise3 |
| `net.ipv4.tcp_notsent_lowat` | 131072 | lower |
| `net.ipv4.tcp_mtu_probing` | 1 | raise |
| `net.ipv4.tcp_slow_start_after_idle` | 0 | lower |
| `net.ipv4.tcp_keepalive_time` / `intvl` / `probes` | 600 / 30 / 5 | lower |
| `net.ipv4.tcp_fin_timeout` | 15 | lower |
| `net.ipv4.tcp_tw_reuse` | 1 | prefer |

`tcp_notsent_lowat` keeps at most 128 KiB of unsent data per relay socket instead of no limit, which lowers queueing delay with BBR. `default_qdisc` applies to interfaces created afterwards or after a reboot.

### Tunnels & routing

| Key | Value | Mode |
| --- | --- | --- |
| `net.ipv4.conf.all.rp_filter` / `conf.default.rp_filter` | 2 (loose) | loose |
| `net.ipv4.conf.all.send_redirects` / `conf.default.send_redirects` | 0 | lower |
| `net.ipv4.conf.all.accept_redirects` / `conf.default.accept_redirects` | 0 | lower |

Strict reverse-path filtering drops replies that return on another interface, which breaks GRE and additional IPs with their own gateway (`--doctor` warns about it). Loose mode still drops sources the host has no route to at all. The kernel uses the larger of `all` and the interface value, so `all = 2` loosens existing interfaces and `default = 2` new ones such as GRE links created later. A forwarder should neither send ICMP redirects (clients would be told to bypass it) nor accept them. HAProxy's `clitcpka`/`srvtcpka` use the keepalive values, which keep idle relay connections inside the one-hour tracking timeout.

## Undo, restore and reset

- **Undo last step** returns every key to the journal as it was before the last apply or group restore. Up to 20 steps are kept.
- **Restore originals** on a group returns its keys to the values from before the panel first changed them; other groups stay.
- **Reset everything** returns every managed key to its original value, deletes the drop-in, the module list, the journal and the undo history.

A key whose live value no longer equals what the panel applied was changed by someone else. Undo, restore and reset leave it as it is, stop tracking it and say so. A write that fails keeps that key tracked for a retry. An apply that fails partway reverts the keys it already wrote.

## Files

| Path | Content |
| --- | --- |
| `/etc/sysctl.d/zz-gre-manager-optimize.conf` | Applied values. The `zz-` name sorts after other drop-ins (including `99-zz-server-tools.conf` and `99-sysctl.conf`), so these values win at boot |
| `/etc/modules-load.d/gre-manager-optimize.conf` | `nf_conntrack` (and `tcp_bbr` when BBR is applied), loaded before `systemd-sysctl` so the keys exist at boot |
| `/etc/gre-manager/optimize/journal.tsv` | `key / before / applied / group`, mode 600 |
| `/etc/gre-manager/optimize/steps/*.tsv` | Undo steps (newest 20) |

Both owned files are rewritten only while they still match what the panel last wrote; an edited file stops the operation and is kept for the operator.

## ServerTools and other drop-ins

When [ServerTools](https://github.com/Sir-Adnan/server-tools) is installed, the page says so. Its settings are left alone until a group is applied here; for keys both set, the panel's value wins at boot, and the page shows the other file and its value next to the key. Rolling ServerTools back later may change those keys again; afterwards the page shows them as changed outside the panel. Other drop-ins that set the same keys are listed the same way and are never edited.

## Upgrading from v1.3.7

`/etc/gre-manager/tuning.tsv` and `/etc/sysctl.d/99-z-gre-manager-owned.conf` from the old tuning menu are imported on the first apply or restore: their original values become the reset target (group *previous*), the old drop-in is replaced by the new one and both are copied to `backups/tuning-import-*`. Historical files of v13.x (`99-gre-tuning.conf`, `98-gre-highload.conf`) are retired separately; see [Retiring old installations](RETIRING-OLD-INSTALLS.md).

## Verification

Local tests cover memory sizing, every never-worse mode against a provider image with better defaults, apply/undo/group restore/reset, failed-apply recovery, external changes, edited files, the ServerTools report and the v1.3.7 import (`tests/test_advanced.py`), plus the Go parsers and the demo simulation. Boot behavior on a real server (module load order, `systemd-sysctl` ordering) has not been verified on a VPS yet.
