# Port ranges, domain destinations and server DNS

This guide covers large port ranges, one-to-one port mapping, destinations given as a domain name, the server's own DNS, and moving from Port Forward Manager (`portfw`). The terminal menus and the web panel use the same Bash engine (`src/state.sh`, `src/resolve.sh`, `src/sysdns.sh`, `src/portfw.sh`).

## Port ranges and mapping

A connection takes up to 32 local ports or ranges separated by commas, for example `443, 8443, 2000-2999`.

- **nftables and iptables** keep a range as **one record and one rule** of up to 4096 ports. 1,000 ports cost the same as one.
- **HAProxy and Realm** open one listener per port, so a range expands to single-port records (at most 32 ports per setup), as before.

How the incoming ports reach the destination:

| Mapping | Example | Record target | Engines |
| --- | --- | --- | --- |
| Same port | 2000-2999 → 2000-2999 | `203.0.113.5:2000-2999` | nftables, iptables |
| One port | 2000-2999 → 443 | `203.0.113.5:443` | nftables, iptables |
| Mapped | 2000-2999 → 3000-3999, 8443 → 443 | `203.0.113.5:3000-3999` | nftables |

Mapped ranges pair ports in order and must be the same size; a single remote port may take a whole range, and several local ranges may share one remote port. iptables keeps the original port or sends every port to one port; shifted ranges need nftables (`iptables` has no portable port-shift).

The record format is unchanged apart from the port fields: `port` may be `first-last` and a target port may be `first-last` of the same length. Earlier releases (v1.4.1 and older) cannot read range records; downgrade with a restore point taken before the first range was saved.

Rules:

- nftables: `tcp dport 2000-2999` with `dnat ip to ADDRESS` (same port), `ADDRESS:PORT` (one port) or an anonymous port map `dnat ip to tcp dport map { 2000 : ADDRESS . 3000, … }` (mapped). Forward, masquerade and MSS rules match the destination range and `ct original proto-dst 2000-2999`.
- iptables: `--dport 2000:2999 -j DNAT --to-destination ADDRESS` (same port) or `ADDRESS:PORT`, with `--ctorigdstport 2000:2999` in the companion rules.
- Listener conflicts are checked across ranges and single ports (both orders) when the state loads, against local sockets with an `ss` range filter, and against legacy and Port Forward Manager rules.
- Clearing tracked flows of a range record (failover, Health → flows) lists the flows of each destination once and deletes them per original port that has flows.

## Domain destinations

A destination can be a DNS name instead of an address, for example `backend.example.com:443`. Names are lowercase, with a letter top-level label (`gtm_hostname`); IP-like strings are never treated as names.

- **On save** every new name must resolve (`getent ahostsv4`/`ahostsv6`, five-second timeout) or the save is refused. Kernel records resolve in their listener's family; relays use IPv4 unless they listen on IPv6.
- **Rules use addresses, never DNS:** the engine keeps the last answer in `/etc/gre-manager/dns-cache.tsv` and expands each name to its addresses when it renders nftables, iptables, HAProxy and Realm configuration. Nothing in the packet path waits for DNS, and the boot reconciler uses the cache.
- **Refresh:** while any enabled record uses a name, `gre-manager-dns.timer` runs every minute and re-resolves only names that are due (default every 5 minutes, 1–60 per name in `dns-policy.tsv`). Address changes and pending policy changes run full preflight before apply, including resolved self-loop checks. A failed lookup keeps the last answer. A checked apply failure restores the previous cache, attempts kernel/relay recovery and keeps `dns-pending` for retry, including after interruption. The timer is removed when no record uses a name.
- **Several addresses:** *All as destinations* (default) makes every address a destination with the name's port and weight, so balancing and health failover apply to them; *Only the first address* uses one stable address. Changing policy reconciles immediately even if the DNS answer is unchanged. Policy is shared by every connection using that name. Up to 16 addresses per name and 32 destinations per record.
- Health checks, failover positions and the Diagnose checklist use the resolved addresses. HAProxy routing records (SNI/HTTP rules) need literal destinations.
- In the panel, the destination field checks a name as you leave it and shows the addresses it resolves to now; Connection details and search include them.

## Server DNS (Optimization → DNS)

Sets the resolvers the server itself uses. It is separate from the kernel groups: **Apply all** and **Undo** never change DNS.

- **Presets:** international (Cloudflare, Google, Quad9, AdGuard, OpenDNS, with optional IPv6) and Iranian (Shecan, Electro, Radar Game, 403.online, Begzar), or one to four manual servers. The list is `panel/internal/model/dns_presets.json`; the terminal menu keeps the same list (a test compares them).
- **Speed test:** from the server, three lookups per server through only that server (UDP 53, two-second timeout), median time. The panel marks the fastest in the shown group.
- **systemd-resolved:** writes `/etc/systemd/resolved.conf.d/90-gre-manager.conf`, explicitly resets inherited `DNS`, `FallbackDNS` and domain lists, then selects `DNS=…` and `Domains=~.`. It restarts resolved and verifies the active global list when `resolvectl` is available. A later overriding drop-in or a failed restart reports failure and triggers file/service recovery. More-specific per-link routing domains still follow resolved's normal routing rules.
- **Plain `/etc/resolv.conf`:** keeps a copy of the original, writes the chosen `nameserver` lines (keeping `search`, `domain` and `options`), and installs `gre-manager-resolv.service`, which writes the file again after `network-online.target` because DHCP clients can replace it at boot.
- **resolvconf and NetworkManager** hosts are reported and not changed: their own tools own the file.
- **Restore original** removes the drop-in or boot unit and puts the original file back exactly.

The panel distinguishes **active global resolvers** from **configured by this manager**. A local stub such as `127.0.0.53` normally remains in `/etc/resolv.conf`; `/run/systemd/resolve/resolv.conf` can still list DHCP-provided servers as well. Their presence alone does not establish which server answers ordinary queries. Query `resolvectl status` when inspecting per-link routing. Apply/restore stage only the known owned files and attempt to restore the immediately preceding configuration on checked failure. A pre-existing manager-path drop-in is retained for exact restore on new managed setup. Plain bind-mounted or read-only resolver files can reject replacement; that failure must be resolved locally rather than shown as a successful change.

Terminal: Tools → **Server DNS**. Engine operations: `dns-status`, `dns-apply SERVER…`, `dns-restore`.

## Port Forward Manager (portfw)

[Port Forward Manager](https://github.com/h-zare-dev/iptables-forward-manager) keeps rules in `/etc/iptables-forward-manager/rules.db` and installs NAT in the `ip ifm_portfw` nftables table (or `IFM_*` iptables chains).

- **Coexistence:** while its NAT is active, a new or changed listener that overlaps one of its source ports is refused, because two managers DNATing the same port is ambiguous. Its files and tables are never changed.
- **Import:** Connections → Import → nftables or iptables → *Port Forward Manager (this server)*. The panel reads the rules through the engine (`portfw-rules`), turns each run of consecutive ports that stays consecutive on the destination side into one range record, keeps domains (all addresses, round robin for nftables), and shows the usual review. Remove the rules from portfw (or stop `portfw-nft`) after importing.

Compared with portfw, this manager adds health checks and failover for the resolved addresses, IPv6, relays, change history and restore, and does not need Python on the server. Timed rotation between addresses is not offered; use round robin with health failover instead.

## Verification

Local evidence: `tests/test_forwarding.py` (ranges, conflicts, nft/iptables rendering, domains, refresh, timer, server DNS on both setups, portfw), Go tests in `internal/model/ports_test.go` and `internal/control/forwarding_test.go`, frontend tests in `tests/forwarding.test.mjs`, and `nft -c` / `iptables-restore` of rendered range rules inside an isolated network namespace. Not yet run on a real server: domain refresh with a changing DNS record, DNS changes on real systemd-resolved and DHCP hosts, and an import from a live portfw installation.
