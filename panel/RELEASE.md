# GRE Tunnel Manager v1.5.3

This release fixes kernel forwarding on servers with Docker/UFW, additional IPs or a changed IP, and the server DNS error on systemd-resolved.

## Forwarding fixes

- **nftables forwards behind Docker/UFW:** both set the iptables `FORWARD` policy to `DROP`. An accept in the manager's nftables table cannot override that drop, so nftables forwards silently stopped while iptables forwards kept working. When iptables is installed, each nftables forward now also gets scoped accepts in the owned `GTM_FWD` chain: only its own DNAT flows and their replies.
- **Additional IPs and IP changes:** kernel `masquerade` used the first address of the egress interface instead of the route's preferred source. With an additional/floating IP or an old address still assigned, the destination (a VPN server abroad, for example) answered an address that never came back. When the egress interface holds several global IPv4 addresses, forwards that masquerade now SNAT to the route's preferred source. Single-address servers keep masquerade. A minute timer reapplies kernel rules when those addresses change.
- **Diagnosis** reports the entrance address (a specific listen IP that left the server fails), the `FORWARD` policy with the owned accept, and the source address the destination sees.

## Server DNS

The systemd-resolved drop-in is now `zz-gre-manager.conf`, so named drop-ins such as `dns.conf` no longer override it. This caused "The resolver did not activate the selected DNS servers". The previous `90-gre-manager.conf` is migrated on the next apply or restore. Verification waits for resolved to settle, accepts newer `resolvectl` output and names any drop-in that still overrides the selection.

## Panel

- Server addresses list the default-route interface first and container bridges last.
- Pairing pre-fills the saved public IP only while it is still assigned, otherwise the uplink's IPv4 address, so a changed server IP no longer proposes a GRE source that preflight rejects.

## Upgrade

Update the terminal script and run the current panel installer to load the matching **v1.5.3** executable/helper, then refresh the browser. Afterwards run **Maintenance → Refresh kernel rules** (or restart `gre-manager-forwarding.service`) so existing forwards receive the new rules, and apply Server DNS once more if it previously failed. Credentials, certificates and managed configuration are retained. Verify `SHA256SUMS`.

Local verification covers the Python suite, Go race/vet, frontend build/lint/tests, ShellCheck and isolated namespace packet tests (including TCP/UDP through an nftables forward under `FORWARD DROP`) with nftables 1.1.6 and iptables-nft 1.8.11. Real Docker/UFW hosts, provider additional IPs and a live systemd-resolved restart remain deployment checks.
