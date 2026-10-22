# User guide

Start with the [README](../README.md). See [Terminal UI](TERMINAL-UI.md) for prompts and header behavior, and [Web panel](WEB-PANEL.md) for browser management.

## Main menu

| Section | Purpose |
| --- | --- |
| 1 · GRE Tunnel | Create, inspect, edit and delete GRE / Simple GRE |
| 2 · Port Forwarding | Manage iptables/nftables forwarding |
| 3 · HAProxy Tunnel | Manage TCP relays, balancing, services and logs |
| 4 · Realm Tunnel | Manage TCP/UDP relays and services |
| 5 · Reverse Tunnel | Configure FRP or rathole |
| 6 · Load Balancing | Choose an engine and multiple destinations |
| 7 · Tools | Status, restore, update, cleanup and help |
| 8 · Web Panel | Optional browser interface and engine preinstallation |

## GRE between two servers

Choose **GRE Tunnel → Kharej Server** on one server and **GRE Tunnel → Iran Server** on the other. These labels identify complementary roles; the servers need not be in those countries.

Use the same ID from 1–250 at both ends. ID 10 gives `10.0.10.1` on the Kharej side and `10.0.10.2` on the Iran side. The default MTU is 1430. Key/address compatibility with v13.7 and later is preserved.

To forward over GRE, use the other endpoint's internal address as the destination. GRE does not encrypt traffic. Deletion checks known modern forwarding references, including disabled entries; manually created routes/rules require separate inspection.

## Creating a forward or relay

Open the engine manager and its add action. Kernel forwards offer **Add iptables forward** and **Add nftables forward**.

1. Enter local ports, for example `443,8443` or `8000-8003`.
2. Enter destination IP and port separately. Combined `203.0.113.20:443` and `[2001:db8::1]:443` are accepted.
3. Select TCP/UDP/both numerically for Realm or kernel forwarding. HAProxy is TCP-only.
4. Review the mapping and save. Names are automatic unless specified; additional settings are optional.

Up to 32 ports are accepted in one setup. Choose whether all map to the entered destination port or preserve their local port numbers. Each local port has its own record/ID; creation uses one apply step and restore point. Existing records are edited individually.

## Listen addresses and source policy

HAProxy and Realm default to all local IPv4 addresses. **Optional settings → Listen address** can choose a specific address or all IPv6 addresses; actual IPv6 behavior also depends on the OS.

Kernel forwarding requires a specific local address. The terminal suggests one from routing information without sending a discovery packet; it asks when no suitable route exists. A cloud-NAT address may be private. Review the address before applying.

The usual source policy is `masquerade`. Preserving client IP for a kernel forward requires a valid destination return route. HAProxy/Realm create a new outgoing connection. HAProxy PROXY metadata requires compatible configuration in the receiving application and does not change the outgoing packet's network source address.

## Load balancing

Open **Load Balancing** inside HAProxy or Realm. Add destinations one at a time using numbered choices. Weights default to one; advanced input `203.0.113.20:443@2` selects weight two.

| Engine | Supported behavior |
| --- | --- |
| Kernel forwarding | TCP/UDP weighted distribution; no destination health checks |
| Realm | TCP/UDP round robin or source hash; no active health checks in this adapter |
| HAProxy | TCP round robin, leastconn, source or primary/backup, with TCP checks |
| FRP | TCP destination groups and connection checks |
| rathole | One destination per instance; no balancing in this adapter |

Balancing selects destinations for new connections; moving an existing connection without interruption is not guaranteed. A successful TCP check does not prove the complete VPN/application is healthy.

## Inspecting, editing and deleting

Each manager lists its own entries. A filtered selection never becomes the complete state being saved. Delete multiple entries using space-separated row numbers. Edits preserve enabled state, source policy and supported advanced options. Concurrent changes to the same record cause stale edits to fail.

Use **Status & Logs** for a selected service and its logs/restart. **Start / Stop** retains configuration while changing enabled state.

## HAProxy options

Open **HAProxy Tunnel → Advanced Settings** and select a connection. Edits remain in the form until **Save & apply**. Options include timeouts, health checks, limits, the VPN preset, PROXY metadata and logging. Choices are numbered; durations and limits use numeric input.

Status is read through a restricted Unix socket. HAProxy's native statistics interface is not exposed publicly. Compatible changes use worker reload with readiness checks; service/file-descriptor changes may require restart. See [HAProxy](HAPROXY.md) for state-v2 compatibility and scope.

## Reverse tunnels

Open **Reverse Tunnel** and choose an engine. Use **Setup Server** on the public entrance and **Setup Client** on the destination. Match service name, control/public ports and shared token. Default names derive from the public port; use distinct names for separate instances.

FRP supports TCP, WS, WSS and QUIC transport choices. TCP Mux here means stream multiplexing, not HTTP CONNECT tcpmux. WSS requires existing certificate/key files at the entrance and trust configuration at the destination. Certificate provisioning and renewal remain the operator's responsibility.

For rathole, transfer only the entrance public key through a trusted channel. Private keys and tokens remain in restricted configuration files. UDP uses a TCP-based transport in this adapter, which can add delay on lossy paths. Removing one endpoint does not remove its peer.

## Restore and cleanup

Use **Tools → Restore Backup** for managed forwarding/relay restore points. TSV snapshots do not restore GRE units, FRP/rathole instances, certificates or global host settings; back those up separately.

**Port Forwarding → Old forwarding rules** handles recognized historical entries. **Tools → Cleanup** accepts only known resources and takes a backup first. Unknown commands/custom services block whole cleanup. See [Tuning and cleanup](TUNING-CLEANUP.md) for partial-failure recovery and global settings.

## Read-only checks

```bash
bash gre.sh --version
sudo bash gre.sh --validate
sudo bash gre.sh --plan
sudo bash gre.sh --doctor
sudo bash gre.sh --haproxy-status F000001
```

Omit `sudo` when root; replace the example connection ID. Checks do not prove end-to-end health or capacity. Plan output contains addresses. See [Operations](OPERATIONS.md) for recovery and real-server validation.

## Browser management

Main-menu option 8 installs/manages the optional panel. It has Persian RTL and English LTR, staged forms, bulk actions and optional accounting. Tunnel engines can also be installed in advance. The current panel manages its own host; remote Nodes/Agents are planned in the [phase-gated roadmap](ROADMAP.md).
