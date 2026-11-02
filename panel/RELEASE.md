# GRE Tunnel Manager v1.3.5

Kernel forwarding that works on servers with additional IPs, steadier applies and a redesigned web panel.

## Forwarding on servers with additional IPs

- New iptables/nftables forwards listen on every local address by default (`0.0.0.0` / `::`), so users can connect through any additional IP. Rules match `fib daddr type local` (nftables) or `-m addrtype --dst-type LOCAL` (iptables). An explicit address still restricts a forward to that IP, and the panel suggests this server's addresses.
- Previously each rule matched one destination address, and the panel defaulted to the first IPv4 the OS listed, which could be a secondary, private or GRE address.
- A wildcard forward conflicts with any other listener on the same port and protocol, and preflight rejects a wildcard forward back to this host's own port. Saved records are unchanged. Older releases reject wildcard kernel records, so a downgrade needs a compatible restore point.

## Reliability

- Replace the owned nftables table atomically instead of flushing it. Existing flows keep their NAT mappings.
- Load state in linear time (300 records: about 20 s to under 1 s), keep the newest 100 automatic restore points and reload systemd once per apply. Realm starts are confirmed by its listener instead of a fixed sleep.
- Keep dashboards responsive during long applies: read actions no longer wait for the mutation lock.
- The panel broker keeps running while the panel restarts, so sampling and opt-in quota pauses continue. A panel upgrade that fails to start rolls back to the previous executable.
- Throttle failed logins per IPv4 address or IPv6 /64 without locking out the administrator. Keep following a running job through temporary network or gateway errors.
- Reject malformed IPv6 spellings such as `:1::2`.

## Web panel

- Three new presets that meet WCAG AA in light and dark mode: **Signal** (Grafana-like, the new default), **Graphite** (Linear-like) and **Aurora**. Nettinx and Neutral stay available and unchanged. Browsers that stored the old automatic Nettinx default move to Signal once; a later choice is kept.
- One **Connections** page for HAProxy, Realm and port forwarding, with engine filters and counts. Old `#/haproxy`, `#/realm` and `#/forwarding` links open the matching filter.
- A status-first overview: host and address, four summary tiles, live telemetry and a **Needs attention** list for failed or stopped services and missing engines.
- A **Ctrl/Cmd+K** command palette for pages, filters, saved connections, new connections and appearance.
- A clear on/off switch per connection, a floating bar for bulk actions, a step indicator in the connection form and roomier mobile layouts.
- Inter for Latin text and digits with Vazirmatn for Persian; short, subtle motion that is disabled under reduced motion.

## Upgrade and verification

Run the current panel installer to install the matching v1.3.5 package, then refresh the browser to load the new interface. Downloading the script alone does not upgrade the executable. Existing credentials, certificates and managed tunnel settings are kept. Use matching Controller/Agent packages when upgrading Nodes.

Linux amd64/arm64 archives contain the executable, embedded frontend, matching Bash helper and dependency notices. Verify `SHA256SUMS`. Managed servers do not need Node.js, Python or a compiler.
