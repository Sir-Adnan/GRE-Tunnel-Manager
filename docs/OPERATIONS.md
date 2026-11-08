# Operations and recovery

## Inspect before applying

```bash
bash gre.sh --version
bash gre.sh --catalog
bash gre.sh --demo
sudo bash gre.sh --validate
sudo bash gre.sh --plan
sudo bash gre.sh --doctor
sudo bash gre.sh --haproxy-status F000001
```

Read-only commands do not require root if the state file is readable. Production state normally lives in a root-only directory. `--validate`/`--plan` accept `--state-file PATH`, including a copied state file or a TSV restore point. They reject a missing/unreadable file; a new installation with no state is normal in `--doctor`.

- `--validate`: schema, backend capabilities, duplicate endpoints, direct listener loops and conflicting managed listeners. Equivalent IPv6 spellings compare equally.
- `--plan`: validation plus generated enabled configurations. No package installation, temporary files, target probes, firewall changes or service restarts. It excludes existing-resource cleanup and separate FRP instances. Output contains topology/IP addresses.
- `--doctor`: available tools, saved-state validity, forwarding switches, conntrack count/limit, GRE interfaces/MTU, per-address routing tables and return rules, single-address kernel forwards and service state. Missing optional tools are informational. No target traffic, bandwidth test or background monitoring is started.
- `--catalog`: implemented adapters, selection tradeoffs and explicitly unimplemented methods. No state file, root or host probes required.

Inspection exit codes: 0 for completed inspection, 1 for invalid/unreadable state or failed HAProxy socket inspection, 2 for invalid CLI arguments. Doctor's exit status reflects saved-state validity, not a guarantee that every host component is healthy. Host status commands can be unavailable or permission-limited.

## What a managed forwarding change does

1. The wizard shows the connection and obtains confirmation. An explicitly requested missing component can be installed here.
2. Under the manager lock, state is reloaded. An editor refuses to overwrite a row changed in another session. Disabled state and source-IP policy remain as selected.
3. A candidate passes record/conflict checks. Enabled connections require a local entrance IP; explicit kernel entrance interfaces must exist. IPv6 forwarding must already be configured.
4. iptables restore test, nft check and HAProxy config check run before live changes. Realm has validated data/rendering; startup remains its runtime validation. These checks cannot prove target reachability, return routing or other firewall policies.
5. The old state is snapshotted, the candidate replaces the state file atomically, and owned kernel/relay resources are reconciled. An unchanged running config and unit are retained. HAProxy additionally needs socat/timeout for local worker verification; compatible config updates reload and wait for a new worker PID, while unit/FD changes restart.
6. On failure after replacement, the previous state is restored atomically. Both kernel and relay recovery are attempted, and recovery failure is reported.

The complete operation is not atomic across kernel tables and systemd. Optional package installation and separate FRP/legacy operations are outside the managed-TSV rollback. Existing sessions can end or retain an old conntrack mapping until normal expiry; the host conntrack table is never flushed.

Port-first setup accepts up to 32 local ports and shows fixed/matching destination-port mapping before apply. It creates a separate record per listener, allocating IDs under one lock and committing the full batch once. Each HAProxy/Realm record still owns its own service, so more listeners also mean more relay processes. Editing remains per record. Names are automatic; advanced source/listen choices and disabled state are preserved during edits.

New relay and kernel forms default to listening on all local addresses (`0.0.0.0`, or `::` for an IPv6 destination). Review exposes this scope and Optional settings can restrict it to one assigned IP. Use the default on servers with additional IPs: clients can connect through any of them. An explicit IP accepts traffic only on that address. A wildcard forward reserves its port and protocol on every address. Preflight rejects a wildcard listener targeting a local address on its own listening port.

IPv4 and IPv6 kernel forwards may share a port, because their rules never overlap. A relay listening on `::` can accept IPv4 too, so mixed relay/kernel pairs still conflict.

Some providers route an additional IP through its own gateway, configured as source policy routing (`ip rule add from X lookup N`). Local sockets follow that rule, but forwarded replies are routed before un-DNAT restores `X` as their source. Without help they leave through the main gateway and the provider's anti-spoofing drops them. On apply, the manager asks the kernel which table `ip route get 1.1.1.1 from X` uses for every global address (`2606:4700:4700::1111` for IPv6). This sends no packets. New flows that enter on such an address get a connection-mark value in bits `0xf000000`, one per table (sorted by table name, at most 15). An owned rule `fwmark M/0xf000000 lookup N` at preference 31001-31015 sends their replies through table `N`. Nothing changes on hosts without per-address tables. Rules are reconciled on every apply and at boot, and are removed with the last kernel forward; foreign `ip rule` entries are never touched. After changing the host's routing policy, apply again (or restart `gre-manager-forwarding.service`). Software that uses the same mark bits, or strict reverse-path filtering (`rp_filter=1`) on that address's interface, can still drop these flows; use `2` (loose) there.

**Source address of forwarded flows.** Kernel `masquerade` takes the first primary address of the egress interface and ignores the route's preferred source (`src`). When that interface holds more than one global IPv4 address (an additional or floating IP, or an old address kept after an IP change) the destination could see, and answer, an address that is not routed back, and the forward silently stops. On apply the manager asks `ip route get DESTINATION` for each masquerading IPv4 destination; when its egress interface has several global IPv4 addresses, the rule uses `snat ip to SRC` (iptables: `-j SNAT --to-source SRC`) with the route's preferred source instead. With one address, masquerade stays and follows DHCP changes by itself. IPv6 keeps masquerade (it uses standard source-address selection). The applied sources are kept in `/run/gre-manager/snat-sources.tsv`; while any source is pinned, the minute refresh timer (`gre-manager-dns.timer`) compares them with current routes and reapplies kernel rules when the host's addresses change. To make the destination see a specific address, put it first as the route's `src` (for example `ip route replace default via GW dev eth0 src ADDRESS`) and apply again.

**Docker, UFW and the FORWARD policy.** Docker and UFW set the iptables `FORWARD` policy to `DROP`. nftables evaluates every base chain on a hook, so an accept in the manager's own table cannot override that drop. When iptables (legacy or nf_tables backend) is installed, nftables forwards therefore also get scoped accepts in the owned `GTM_FWD` chain, hooked first in `FORWARD`: only DNAT flows of each forward to its own destinations, and their replies. NAT, MSS and balancing stay in nftables. Firewalls that drop forwarded packets in their own nftables base chains (firewalld, custom tables) still need a rule there. The connection diagnosis reports the entrance address, this policy and the source address the destination sees.

`--doctor` lists addresses with their own routing table and whether their return rule is active. It warns about strict `rp_filter` and lists explicit-bind kernel forwards on hosts with other addresses of that family. Records saved before v1.3.5 kept their single address; edit **Listen address** to all local addresses to accept on every IP.

## Restore or investigate a failure

For a reinstall or a move to another server, use the panel's encrypted [Backup & restore](BACKUP-RESTORE.md) workflow. It includes recognized GRE/reverse definitions and optional accounting. The terminal restore points below have a narrower scope.

Use **Tools → Restore Backup**. Select a snapshot, inspect its generated preview, then confirm. Restoration goes through the same validation/preflight/apply path and creates another snapshot. It restores managed forwarding records, not FRP instances, GRE units, optional binaries or operator certificates. The newest 100 automatic restore points are kept. Set `GTM_RESTORE_POINTS` for another count, or `0` to keep all. Cleanup, tuning, legacy and manually named files are never pruned.

```bash
sudo journalctl -u gre-manager-forwarding.service -n 100 --no-pager
sudo journalctl -u gtm-F000001.service -n 100 --no-pager
sudo bash gre.sh --doctor
```

Replace the example connection ID with the reported ID. If rollback reports failure, inspect the saved state and logs before another change; saved desired state and live resources may differ. Do not execute a legacy backup shell file from an untrusted source.

HAProxy staged settings/status, PROXY requirements and restart cases are documented in [HAPROXY.md](HAPROXY.md). Retiring v13.x resources is documented in [Retiring old installations](RETIRING-OLD-INSTALLS.md) and server-wide settings in [Server optimization](OPTIMIZATION.md). Do not restore a forwarding snapshot expecting it to roll back host settings or a reverse-connection config.

For nftables, the owned iptables accept covers Docker/UFW `FORWARD` DROP policies; inspect other nftables base chains (firewalld, custom tables), since an ACCEPT in the manager table does not override their DROP. For source-preserving forwarding, verify return routes. For stalls after small packets succeed, inspect path MTU and ICMP delivery on both peers.

## Rathole reverse connections

Choose **Reverse Tunnel → rathole**. On the public entrance choose **Setup Server**; on the private/destination host choose **Setup Client**. Match the instance name, service protocol, control TCP port and token. The generated service names append `_tcp`/`_udp`, so select the same protocol set on both peers. Copy the entrance's displayed Noise public key over a trusted channel. The private key stays in its mode-600 server config. Do not copy private keys, tokens or entire configs into public logs.

The entrance binds a control TCP listener and public TCP/UDP service port(s) to the selected local IP. Allow them explicitly in host/provider firewalls. UDP service traffic also travels through Noise over TCP; this preset has no QUIC or UDP underlay. One destination per instance; use FRP destination groups or HAProxy for the relevant load-balancing scenario.

The installer pins rathole 0.5.0 release archives with SHA-256, supports x86_64 GNU/Linux and aarch64 musl, and requires curl/unzip/sha256sum/install. It verifies the downloaded binary can execute before installation. An existing unsupported version is reported and retained. No automatic upgrades or claim that later upstream main features work with this pin.

Local files: `/etc/gre-manager/gtm-rathole-ROLE-NAME.toml` and `/etc/systemd/system/gtm-rathole-ROLE-NAME.service`. Review status with `--doctor` or `journalctl -u gtm-rathole-entrance-NAME`. A running process does not prove successful peer authentication, target reachability or packet transfer. The preset has schema validation and startup checks; rathole 0.5.0 has no separate native offline config verifier in this adapter.

**List / remove** stops/disables only the selected local service and removes its owned config/unit. A stop failure retains files for recovery. Removal on one host does not remove its peer. Recreate with a new key to rotate credentials and coordinate the destination; automatic editing/hot reload is not offered yet. FRP/rathole configs remain outside TSV restore points; the encrypted [portable backup](BACKUP-RESTORE.md) includes recognized generated reverse definitions and their secrets.

## Remove a GRE link

The delete action lists managed connections referencing `greID`, `gre-out-ID`, `10.0.ID.0/30` or `fd00:ID::/64`. Disabled records also block deletion because re-enabling them would recreate a broken connection. Edit or delete those connections first, then confirm link removal.

This protects the default managed address/interface contracts. Custom routing, manually edited addresses, legacy rules and separate FRP endpoints are outside the dependency model. Review them before deleting. No dependent forwarding record is silently deleted.

## High latency that a reboot fixes

Rising ping and jitter over hours, cleared by a reboot, usually mean the connection-tracking table is filling with abandoned client connections (the kernel keeps idle TCP entries for five days by default). Reapplying kernel rules does not help: existing flows keep their NAT mappings. Check **Health → Server** or run:

```bash
sysctl net.netfilter.nf_conntrack_count net.netfilter.nf_conntrack_max net.netfilter.nf_conntrack_tcp_timeout_established
cat /sys/module/nf_conntrack/parameters/hashsize
sudo conntrack -S
```

Apply **Connection tracking** on the Optimization page: idle TCP entries expire after one hour and the table and its hash are sized to the server's memory ([Server optimization](OPTIMIZATION.md)). For a forward with several destinations, turn on health failover so a dead destination stops receiving new connections. To recover one forward without a reboot, a maintenance **Restart** clears only that forward's tracked flows; its clients reconnect. To rule out the destination, restart its proxy first: rebooting this server also drops every connection to the destination. See [Health and maintenance](HEALTH-AND-MAINTENANCE.md).

## Deployment checks still requiring real hosts

Namespace checks cover actual GRE/NAT/relay packets in isolation. Before replacing a production installation, verify the actual two-server path, reboot readiness, systemd sandbox behavior, provider GRE/UDP policy, IPv6 RA, UFW/Docker integration, certificate renewal, large packets and long-lived sessions. Measure load with the intended TCP/UDP workload before choosing limits or claiming capacity.
