# GRE Tunnel Manager v1.5.0

Large port ranges in one kernel rule, domains as destinations, the server's own DNS, and a new connection editor with health and safe apply built in.

## Ports and destinations

- **Port ranges:** a range such as `2000-2999` (up to 4096 ports) is one nftables/iptables record and one rule, so 1,000 ports cost the same as one. HAProxy and Realm still take one listener per port.
- **Remote ports:** *Same port*, *One port* (every port to one destination port) or *Mapped* in order, such as `2000-2999 → 3000-3999` (nftables), with a live preview.
- **Domain destinations:** a destination can be a name such as `backend.example.com:443`. It is checked when you leave the field, and its addresses are shown. Rules always use cached addresses, so nothing in the packet path waits for DNS. A minute timer re-checks each name every 1–60 minutes (default 5) and changes rules only when an address changes; a failed lookup keeps the last addresses. *All addresses* makes each one a balanced, health-checked destination; *Only the first* keeps one stable address.
- **Search** finds a port inside a range and a connection by its resolved addresses.

## Server DNS

**Optimization → DNS** sets the resolvers the server itself uses: international presets (Cloudflare, Google, Quad9, AdGuard, OpenDNS) and Iranian presets (Shecan, Electro, Radar Game, 403.online, Begzar), or up to four manual servers. A speed test runs from the server and marks the fastest. The setting survives reboots and DHCP renewals (a systemd-resolved drop-in, or a boot unit for a plain `resolv.conf`), and **Restore original** puts the exact previous configuration back. Hosts whose DNS is owned by resolvconf or NetworkManager are reported and left unchanged. The terminal has the same choices under **Tools → Server DNS**.

## A new connection editor

- Three steps — **Entrance**, **Destinations**, **Protection & review** — beside a live **route map**; on phones the map folds into the summary bar.
- **Health and protection in the form:** turn health checks on if they are off, and choose *Monitor this connection*, *Automatic failover* and *Notify me* per connection. GRE forms and a shield button on GRE cards offer the same, and lists show a health dot per row.
- **Safe apply:** a change reverts itself after 2, 5 or 10 minutes unless you press *Keep changes* in the banner. The server reverts on its own, even with the browser closed, and only if nothing else changed meanwhile.
- **Duplicate** a connection onto the next free port or range.

## Drag and drop

Reorder connections, destinations (their order is the failover priority), GRE and reverse tunnels, Nodes and the Overview blocks with the mouse, by touch, or with the arrow keys on a focused handle. The order is saved on the server for every device and never changes configuration.

## Moving from Port Forward Manager

**Connections → Import → Port Forward Manager (this server)** turns its rules into range records, keeping port mapping and domains, behind the usual review. While its NAT is active, the panel refuses listeners that overlap its ports instead of DNATing the same port twice. Its files and tables are never changed.

See [Port ranges, domain destinations and server DNS](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/PORTS-AND-DNS.md).

## Upgrade and verification

Run the current panel installer to install the matching v1.5.0 package, then refresh the browser. Existing credentials, certificates and managed tunnel settings are kept. Range records cannot be read by v1.4.1 or older; to downgrade, restore a point taken before the first range was saved.

Linux amd64/arm64 archives contain the executable, embedded frontend, matching Bash helper and dependency notices. Verify `SHA256SUMS`. Managed servers do not need Node.js, Python or a compiler.

Checked locally with Python, Go (race, vet) and frontend tests, ShellCheck, isolated network-namespace tests, `nft -c` and `iptables-restore` of range rules, and browser checks in both languages on desktop and phone. Not yet checked on real servers: domain refresh against a changing DNS record, server DNS on real systemd-resolved and DHCP hosts, an import from a live Port Forward Manager installation and traffic through range rules.
