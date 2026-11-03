# GRE Tunnel Manager v1.3.6

Kernel forwards now work on additional IPs that have their own gateway, and IPv4/IPv6 forwards can share a port.

## Additional IPs with their own gateway

- Some providers route an additional IP through a separate gateway, set up as source policy routing (`ip rule add from X lookup N`). Forwarded replies are routed before their source changes back to that IP, so they left through the main gateway and the provider dropped them. HAProxy/Realm were not affected.
- On apply, the manager finds each address's routing table with a route lookup that sends no packets. Flows entering on such an address get a connection mark (bits `0xf000000`). An owned `ip rule` at preference 31001-31015 sends their replies through the same table. Both iptables and nftables are covered.
- Servers without per-address tables get exactly the same rules as before. The return rules are reconciled on every apply and at boot and removed with the last kernel forward; other `ip rule` entries are never touched.
- After changing the server's routing policy, apply again or restart `gre-manager-forwarding.service`. Strict reverse-path filtering (`rp_filter=1`) on that address's interface still drops these flows; use `2` (loose).

## Other changes

- IPv4 and IPv6 kernel forwards can use the same port. A relay on `::` and a kernel forward on the same port still conflict, because the relay can accept IPv4.
- `--doctor` (and Doctor in the panel) lists addresses with their own routing table and whether their return rule is active. It warns about strict `rp_filter` and names kernel forwards that still listen on one address, such as records saved before v1.3.5. Saved records are not changed; set **Listen address** to all local addresses to accept on every IP.

## Upgrade and verification

Run the current panel installer to install the matching v1.3.6 package, then refresh the browser. Downloading the script alone does not upgrade the executable. Existing credentials, certificates and managed tunnel settings are kept. Use matching Controller/Agent packages when upgrading Nodes.

Linux amd64/arm64 archives contain the executable, embedded frontend, matching Bash helper and dependency notices. Verify `SHA256SUMS`. Managed servers do not need Node.js, Python or a compiler.

Tested in isolated Linux network namespaces and CI, including a policy-routed address with modelled upstream anti-spoofing. Not yet verified on a real provider network.
