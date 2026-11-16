# IP addresses

The **IP addresses** page (Network → IP addresses) shows this server's addresses and what uses each. It moves saved settings to a new address after an IP change and keeps additional addresses in owned units. The terminal has the same change under **Tools → IP changed**. Both use one engine module, `src/addresses.sh`.

## What uses an address

`address-uses` lists every place an owned resource uses a literal address, as `USE ADDRESS KIND ID PRESENT EDITABLE` rows:

| Kind | `local` (this server's address) | `remote` (another server's address) |
| --- | --- | --- |
| `gre` | `local` of the owned `gre-tun-N.service` tunnel line | `remote` of that line |
| `connection` | the record's listen address (`bind`) | each destination address |
| `reverse` | frp `bindAddr`/`proxyBindAddr`, rathole `bind_addr` | frp `serverAddr`, rathole `remote_addr` |

Wildcard listen addresses (`0.0.0.0`, `::`) and domain destinations are not uses; they need no change. `PRESENT` says whether a local address is still on the server. A local address in use that is not present is **stale**. The Overview lists it first under **Needs attention** (derived from inventory alone), and the page shows a banner with **Fix now**.

A WSS reverse entrance also has an HTTPS gateway (`gtm-gateway-*.conf`) bound to the address. That use is listed as not editable: delete the entrance and create it again with the new address.

## IP changed

One screen: choose whose address changed (**This server** or **Another server**), the old and the new address, review the checklist and apply.

- For this server the new address must already be on it. The suggested one is the first address of the same family on the main interface. When the server has no other address of that family, add it first as an additional IP.
- Connections move first, in one locked commit with a restore point. Listeners are checked and the commit rolls back on failure. Destinations keep their ports and weights, and IPv6 keeps its brackets.
- Then each GRE unit and reverse config is rewritten on its own. Only the address token changes, so older units keep their wire defaults. frp configs are checked with `frps|frpc verify`. A unit that was running is restarted and must stay active, otherwise its previous file is restored.
- `address-replace OLD NEW USE ITEM…|all` prints `result ID done|failed` for every item and exits 1 if any failed. The panel shows these per item. Unrelated records, resources and host settings are never touched.

The other end of a tunnel still points to the old address until it changes too:

- **Automatic through Nodes.** When the other end of these GRE tunnels is a remote Node that is online with operations enabled and runs an Agent of v1.6.0 or later, the panel queues one paired job (`POST /api/nodes/readdress`). Both servers check their GRE units, then move their side: `local` on the server whose address changed, `remote` on the other. The job then waits for **Tunnel works — keep**. Without confirmation, or on **Return to the old address**, both sides move back. It uses the job stages, leases and receipts of [paired connections](PAIRED-CONNECTIONS.md). A Node is matched when its inventory reports the same `gre-tun-N` with the old address at the other end. Only one Node is moved automatically per change.
- **Command for other servers.** For any other peer the page shows the command to run there, `sudo bash gre.sh --api address-replace OLD NEW remote all` (`local` when another server's own address changed). Download `gre.sh` there first, or on a server that runs the panel use `/usr/local/lib/gre-manager/manager.sh` in its place.

Older Agents reject the new task kind safely (`invalid_task`), and the job rolls back. No capability flag was added, so older Controllers and Agents keep pairing with this release.

### Paired task details

`readdress-check OLD NEW USE` prints a SHA-256 over the GRE units whose `USE` address is `OLD` and fails when there are none. `readdress-apply REVISION OLD NEW USE` exits 75 when that digest no longer matches (`preflight_changed`), moves every such unit and prints the digest of the moved set. Confirmation requires the same digest computed for `NEW`; rollback applies the reverse change against it, so a unit changed by hand in between is never overwritten.

## Additional IPs

**Add IP** takes `ADDRESS/PREFIX` (a bare address means `/32` or `/128`), the interface (the main one by default) and the return route:

- **Same as main** (default): only `ip address replace` runs; replies follow the main routing table.
- **Separate gateway**: for a provider that gives the address its own gateway. The unit also adds `default via GW dev IF table T` and `rule from ADDRESS table T priority T` with `T = 25200 + N`, and removes both when it stops.

Each address is one owned, enabled `gtm-addr-N.service` (N 1–32, header `# GTM managed address v1`, only `/sbin/ip` commands). A unit that does not start is disabled and removed again. After start the result shows whether the address is on the interface and, with a gateway, whether `ip route get GATEWAY from ADDRESS` finds a route. Kernel forwards are reapplied so per-address reply marks pick up the new table (see [Operations](OPERATIONS.md)). Removing an address is refused while a local use still has it. Units that are not owned are never listed or changed.

Additional addresses are server state, not saved forwarding records. They are not part of TSV restore points or portable backups. Add them again on a new server.

## Limits

- Moving is per address family. IPv4 cannot move to IPv6.
- The Overview warning needs only inventory, so it covers connection listen addresses and GRE local ends. The page also lists reverse configs.
- Health, traffic and history keep their IDs; nothing is renamed.
- Checks run on this server only. After a change, open a connection's **Check** tab or the GRE quality test to see traffic flow end to end.

Local evidence is unit tests (`tests/test_addresses.py`, `panel/internal/control/addresses_test.go`, `panel/internal/nodes/readdress_test.go`, `panel/web/tests/addresses.test.mjs`) and the demo. Real provider IP changes and gateway policies still need checks on real hosts.
