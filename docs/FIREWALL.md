# Firewall

The **Firewall** page (Network → Firewall) shows how the host firewall treats each connection and changes only the manager's own rules:

- per-connection access rules;
- abuse protection;
- ports opened in UFW with a tag.

The host ruleset is never flushed, and other UFW rules, Docker chains or foreign nftables tables are never edited. The engine module is `src/guard.sh`.

On the **Connections** page, badges on each connection summarize its firewall state (forward blocked, closed in UFW, allow or block list, limited) and open its row here. A connection's **Check** tab shows where its packets stop, including drops by a backend and by its access rules, and offers the same fix. See [Web panel](WEB-PANEL.md#connections-and-configuration).

## What the page shows

**Needs attention** lists what blocks traffic now, each item with its fix:

| Finding | Meaning | Fix |
| --- | --- | --- |
| *{backend} drops forwarded traffic and the accept is missing* | An iptables backend (nf_tables or legacy) has `FORWARD` policy `DROP` and no owned `GTM_FWD` jump, so kernel forwards of that family are blocked | **Fix now** reapplies kernel rules (`kernel-refresh`); the accept goes into every dropping backend |
| *Settings saved but not loaded* | `firewall.tsv` asks for rules but `inet gtm_guard` is missing | **Fix now** |
| *nftables is not installed* | Access rules and protection need `nft` | Install nftables (Tunnel engines) |
| *UFW blocks incoming traffic and port … is not open* | UFW drops incoming traffic and a relay (HAProxy, Realm) port has no allow rule | **Open in UFW** for that connection |
| *firewalld is active* | Its own nftables chains may still drop forwards | Allow the ports in firewalld |

The status tiles show:

- **UFW:** state, and the incoming and routed policies.
- **iptables backends:** every backend the kernel uses, its `FORWARD` policy and whether the owned accept is installed.
- **nftables:** availability, and other tables such as `inet abuse_defender`.
- **Host:** the uplink (default-route interfaces), SSH ports, Docker and firewalld.

### Why two iptables backends matter

`iptables` may be the nf_tables variant while UFW keeps its rules in `iptables-legacy`, or the reverse. Packets pass both backends, so a `DROP` in either blocks a forward.

The forward accept is installed in every backend whose `FORWARD` policy is `DROP`. Legacy tables are detected through `/proc/net/ip_tables_names`, so probing never loads legacy modules.

After `ufw reload`, the minute refresh timer reinstalls a missing accept. That timer runs while such a backend exists. See [Operations](OPERATIONS.md#what-a-managed-forwarding-change-does).

## Ports and UFW

Kernel forwards (nftables, iptables) pass the `FORWARD` chain, where the manager keeps its own accept. They need no UFW rule.

Relays listen on this server, so a UFW that denies incoming traffic must allow their ports.

**Open in UFW** adds `ufw allow proto tcp|udp to any port P comment gtm-F000001` for each protocol of the connection:

- **Port changes:** the rule follows the connection's port.
- **Removal:** the rule is removed when the connection is deleted, disabled or the switch is turned off.
- **Existing rules:** a port that another allow rule from anywhere already opens is never added. Closing therefore never removes a rule the operator wrote.

The rules the manager added are tracked in `/etc/gre-manager/ufw-opened.tsv`.

## Access rules

Each connection can limit who may use it:

| Setting | Effect |
| --- | --- |
| Everyone / Only these / Everyone but these | Source allow list or deny list. Entries are addresses or networks; host bits are cleared (`203.0.113.7/24` becomes `203.0.113.0/24`), at most 128 entries |
| Connections per source | Concurrent connections one address may hold (`ct count`), 0 = off |
| New connections per second | Per source (`limit rate` in a dynamic set), 0 = off |

Rules sit in `chain access` (prerouting priority −160), after conntrack and before DNAT. They therefore cover kernel forwards and relays alike, and match only traffic to this host's own addresses (`fib daddr type local`, or the connection's listen address).

The rules apply to new connections; established ones continue. An allow list must contain at least one source of the connection's address family. A disabled connection keeps its settings but loses its rules.

Each rule counts the packets it drops; the page shows the total per connection.

## Abuse protection

Providers send abuse reports when a server scans private networks or sends spam. Both switches act only on **new** connections leaving through the uplink (the default-route interfaces), in the `forward` and `output` hooks. This covers the server, its containers and local VPN clients.

- **Block private ranges:** `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `100.64.0.0/10` and `fc00::/7`.
  - Replies to clients on private addresses and other interfaces (GRE, private networks, Docker bridges) are unaffected.
  - **Allowed private destinations** add exceptions.
  - The default gateway, this server's resolvers and connection destinations in private ranges are always excepted. For example, an Iranian DNS such as `10.202.10.10` keeps working.
- **Block outgoing mail:** TCP port 25. Submission ports 465 and 587 stay open.

## Automatic revert

A change can be applied with **Undo unless confirmed** (off, 60 s, 2 min or 5 min).

1. The engine keeps the last confirmed settings in `firewall.tsv.revert`.
2. It starts a transient systemd timer, `gre-manager-firewall-revert`, that runs `apply.sh --firewall-revert`.
3. Unless **Keep** is pressed in time, the server restores the settings by itself, even if the panel or the SSH session is cut off.
4. Further unconfirmed changes keep the first snapshot.

## Engine operations and files

| Operation | Input | Effect |
| --- | --- | --- |
| `firewall-status` | none | Read-only report (see `parseFirewallStatus` in `panel/internal/control/firewall.go`) |
| `firewall-apply SECONDS` | stdin: the expected revision (`none` or SHA-256 of `firewall.tsv`), then settings lines | Validates under the lock, writes `firewall.tsv`, loads `inet gtm_guard`, syncs UFW. SECONDS 30–900 arms the revert; 0 applies without it |
| `firewall-confirm` | none | Stops the timer and drops the snapshot |
| `firewall-revert` | none | Restores the snapshot now |

The panel adds `firewall-repair`, which runs `kernel-refresh`.

`firewall.tsv` lines (tab separated):

```
protect  private|smtp  0|1
except   CIDR
access   ID  off|allow|deny  PER_IP  RATE  CIDR,CIDR…|-
ufw      ID
```

Every kernel apply (each saved change and boot) reapplies the guard table and the UFW openings from the records. A failure there is reported but never blocks forwarding.

The owned files and runtime objects are listed in [Server artifacts](ARTIFACTS.md).

## Verification

- **Unit tests:** `tests/test_firewall.py` covers validation, revision checks, rendering, the revert flow and UFW tagging (with a stub that refuses duplicate rules).
- **Packet tests:** `tests/linux_namespace.sh` sends real TCP traffic through an allow list, a deny list and private-range blocking with an exception.
- **Go:** `firewall_test.go` covers report parsing, canonicalization and the demo.
- **Web:** `tests/firewall.test.mjs` covers findings and draft edits.
- **Not covered locally:** real UFW hosts and abuse-report scenarios remain deployment checks.
