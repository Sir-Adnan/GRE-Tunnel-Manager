# User guide

**English** · [فارسی](fa/USER-GUIDE.md)

Tunnels and forwards are managed in the web panel. Install it as described in [Install, update and remove](INSTALL.md). Since v1.6.0 there are no terminal menus: `gre.sh` is the panel's engine, and run without arguments it installs or updates the panel.

## Where things are

| Panel page | Purpose |
| --- | --- |
| Overview | Live dashboard: server status, live traffic, connections with their speed, tunnel health and the items that need attention |
| Connections | iptables/nftables forwards, HAProxy and Realm relays: create, edit, balance, enable/disable |
| Traffic usage · Health | Optional per-connection accounting: live speed of each connection, busiest connections, usage this cycle and quotas; uptime and outage history |
| Nodes | Other servers, coordinated GRE/FRP setup between two servers |
| GRE tunnels · Reverse tunnels | Server links and FRP/rathole reverse connections on this server |
| Firewall · IP addresses | Host firewall and access rules; what uses each address, IP changes and additional IPs |
| Maintenance · Optimization | Scheduled refresh/restart, conntrack pressure; opt-in kernel and network-card settings |
| Tunnel engines | Install and update iptables/nftables, HAProxy, Realm, FRP and rathole |
| Change history · Backup & restore | Restore points for managed forwards; encrypted portable backups |
| Settings | Language, appearance, HTTPS certificate, password, two-factor sign-in and sessions, notifications, metrics export and updates |

**Ctrl K** (or the search button on phones) jumps to any page, connection or creation form.

## Tunnel to a foreign server

The common setup: users connect to an entrance server, and their traffic travels through a GRE tunnel to a foreign server where the service runs. Install the panel on the entrance server and open **Connections → Two servers** (also in Ctrl K as **Tunnel to a foreign server** and in the Overview's **Get started** list):

1. **Tunnel:** the foreign server's public IP. This server's address, the lowest free tunnel ID and MTU 1430 are filled in; change them if needed. Both addresses must be the same IP version.
2. **Ports:** the public ports on this server (`443`, `443,8443` or `2000-2100`) and the protocol. The foreign server receives the same port numbers. Turn **Forward ports through the tunnel** off to create only the tunnel.
3. **Review:** the route (users → this server → GRE → foreign server, with the inner addresses) and the values to enter on the foreign server, each with a copy button.

**Create** adds the GRE tunnel with this server as Side B (`10.0.ID.2`) and then a kernel forward to the foreign end `10.0.ID.1`. If the forward fails, the tunnel is kept, the reason is explained, and **Try again** retries only the forward. On the foreign server, install the panel and add the same tunnel under **GRE tunnels** with role Kharej / Side A, this server's IP as the other server and its own IP as the listen address. Allow IP protocol 47 between the servers, including any provider firewall. **Open Health** afterwards shows when the tunnel comes up.

When both servers are Nodes, **Nodes → Connect two servers** creates both GRE ends from one form instead; see [Connect two servers through Nodes](PAIRED-CONNECTIONS.md).

## GRE between two servers

Open **GRE tunnels** on each server and create the tunnel with opposite roles: Kharej on one side, Iran on the other. The labels only name complementary roles; the servers need not be in those countries. With Nodes, **Nodes → Connect two servers** sets up both ends from one form.

Use the same ID from 1–250 at both ends. ID 10 gives `10.0.10.1` on the Kharej side and `10.0.10.2` on the Iran side. The default MTU is 1430. Key/address compatibility with v13.7 and later is preserved.

To forward over GRE, use the other endpoint's internal address as the destination. GRE does not encrypt traffic and needs IP protocol 47 between the servers. Deletion checks known managed forwarding references, including disabled entries; manually created routes/rules require separate inspection.

## Creating a forward or relay

Open **Connections → New connection** and choose the method.

1. Enter local ports, for example `443,8443` or `8000-8003`.
2. Enter the destination IP and port. Combined `203.0.113.20:443` and `[2001:db8::1]:443` are accepted.
3. Choose TCP, UDP or both for Realm or kernel forwarding. HAProxy is TCP-only.
4. Review the mapping and apply. Names are automatic unless you set one; advanced settings are optional.

Up to 32 ports or ranges are accepted in one setup. For iptables/nftables a range such as `2000-2999` (up to 4096 ports) stays one record and one rule; HAProxy and Realm get one record per port. Ports map to the entered destination port, keep their local numbers, or (nftables) map in order to other ports such as `3000-3999`. The destination can be a domain name: it is checked when entered and refreshed every 5 minutes. See [Port ranges, domains and DNS](PORTS-AND-DNS.md), which also covers the server's own resolvers.

## Listen addresses and source policy

HAProxy and Realm default to all local IPv4 addresses. Kernel forwarding also defaults to all local addresses of the destination family: `0.0.0.0`, or `::` for an IPv6 destination. **Advanced → Listen IP** limits a connection to one assigned address; the panel suggests this server's addresses. An all-addresses forward reserves its port and protocol on every IP, so the port must be free on all of them. Additional IPs on a separate interface or gateway may also need policy routing for replies; see [IP addresses](IP-ADDRESSES.md). A cloud-NAT address may be private; review the address before applying.

The usual source policy is `masquerade`. On a server whose uplink interface holds several IPv4 addresses (an additional IP, or an old address after an IP change), the manager uses the route's preferred source address instead, so the destination always answers an address that reaches this server; see [Operations](OPERATIONS.md). On hosts with Docker or UFW, nftables forwards also get an owned iptables accept so their `FORWARD` DROP policy does not block them. Preserving the client IP for a kernel forward requires a valid destination return route. HAProxy/Realm create a new outgoing connection. HAProxy PROXY metadata requires compatible configuration in the receiving application and does not change the outgoing packet's network source address.

## Load balancing

Add more than one destination to a connection. Weights are relative shares, not priorities: a higher value directs more new connections toward that destination when the algorithm uses weights. They default to one.

| Engine | Supported behavior |
| --- | --- |
| Kernel forwarding | TCP/UDP weighted distribution; no destination health checks |
| Realm | TCP/UDP round robin or source hash; no active health checks in this adapter |
| HAProxy | TCP round robin, leastconn, source or primary/backup, with TCP checks |
| FRP | TCP destination groups and connection checks |
| rathole | One destination per instance; no balancing in this adapter |

Balancing selects destinations for new connections; moving an existing connection without interruption is not guaranteed. A successful TCP check does not prove the complete VPN/application is healthy.

## Editing and deleting

Lists can be filtered and sorted, and several entries can be selected for bulk enable, disable or delete. A filtered selection never becomes the complete state being saved. Edits preserve enabled state, source policy and supported advanced options; a concurrent change to the same record makes the stale edit fail. A connection's actions include its service status, recent logs and restart.

HAProxy options (timeouts, health checks, limits, the VPN preset, PROXY metadata and logging) are under the connection's advanced settings. Compatible changes use worker reload with readiness checks; service/file-descriptor changes may require restart. See [HAProxy](HAPROXY.md).

## Reverse tunnels

Open **Reverse tunnels** on each server: the public entrance and the destination. Match service name, control/public ports and shared token. FRP supports TCP, WS, WSS and QUIC transports. TCP Mux here means stream multiplexing, not HTTP CONNECT tcpmux. WSS requires existing certificate/key files at the entrance and trust configuration at the destination.

For rathole, copy only the entrance public key to the destination through a trusted channel. Private keys and tokens remain in restricted configuration files. UDP uses a TCP-based transport in this adapter, which can add delay on lossy paths. Removing one endpoint does not remove its peer.

## Restore and cleanup

**Change history** restores managed forwarding/relay restore points. They do not restore GRE units, FRP/rathole instances, certificates or global host settings; **Backup & restore** creates an encrypted portable backup of the server's configuration ([Backup and restore](BACKUP-RESTORE.md)).

Servers set up with the v13.x scripts can retire their old forwarding script, Simple GRE and tuning files; see [Retiring old installations](RETIRING-OLD-INSTALLS.md).

## Read-only checks

```bash
bash gre.sh --version
sudo bash gre.sh --validate
sudo bash gre.sh --plan
sudo bash gre.sh --doctor
sudo bash gre.sh --haproxy-status F000001
```

Omit `sudo` when root; replace the example connection ID. On a panel server the engine is also installed as `/usr/local/lib/gre-manager/manager.sh`. Checks do not prove end-to-end health or capacity. Plan output contains addresses. See [Command line](COMMAND-LINE.md) and [Operations](OPERATIONS.md).
