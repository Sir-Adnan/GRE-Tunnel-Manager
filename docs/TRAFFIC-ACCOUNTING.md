# Traffic accounting

The full traffic accounting workspace is optional and local to the panel server. Other Nodes can separately opt into [read-only traffic summaries](REMOTE-TRAFFIC.md). Open **Traffic usage** for the **Usage & cycles** and **Traffic collection** tabs. Collection and retained chart history are off by default. Tunnel engines continue to work independently of the panel.

## Track a port or customer

1. Create a forward with a dedicated entrance port. A batch of ports creates independent connection IDs, so each port can have its own accounting.
2. In **Traffic collection**, enable collection, choose all supported connections or a subset, and save. The interval is 15–3600 seconds; 60 seconds is the default. Port accounting requires nftables even when the forwarding engine is HAProxy, Realm or iptables.
3. In **Usage & cycles**, select the connection. Search by name, entrance port or customer label; filter by engine.
4. Open **Customer & quota**. Enter an optional customer/reference label, quota in GiB and the counted direction: received, sent or their sum. Zero means unlimited.
5. Export the filtered list as CSV when needed. Values are quoted and leading spreadsheet formulas are neutralized. The export contains recorded byte values as well as resource IDs and cycle timestamps.

A customer label is a reference, not a user account. Multiple users sharing the same entrance port cannot be separated by these network counters. Use separate ports/connections when attribution matters. There is no customer billing portal or invoice calculation.

## Start a new cycle

**Reset usage** requires confirmation. The broker captures pending samples when collection is active, archives the current cycle and moves the selected resource's application baseline. It does not zero kernel/interface counters, recreate the tunnel, change its port, or change another resource's cycle. Lifetime recorded totals remain available. Up to 12 completed cycle summaries, including the customer label at reset time, are retained per resource.

Resets and policy edits use a ledger revision. An old dialog or repeated request is rejected after a competing management change. The dialog captures the resource identity and revision when opened; a background refresh cannot retarget the operation. A persistence failure restores the previous in-memory cycle. If active counters cannot be read, reset fails instead of silently discarding pending bytes.

When collection is paused, a reset uses the last recorded totals; unmeasured traffic cannot be recovered. Reusing a deleted GRE/reverse technical ID can associate it with the old accounting key: export and **Forget archived usage** before creating a replacement with that ID if a separate ledger is required.

## Quotas and manual controls

Quotas are **advisory**, evaluated against the current cycle. The panel displays progress and a quota-reached badge. It does not automatically stop tunnels or modify firewall policy in the background.

For a forwarding connection, **Disable** uses the existing revision-checked network operation and requires confirmation. It may close relay connections. Existing kernel DNAT connections can remain until their normal conntrack expiry; disabling is not a hard byte cutoff. No host conntrack flush is performed. Enable/delete the connection from its dedicated engine page. GRE/reverse service lifecycle remains in its own manager to avoid accidentally interrupting a management route from the accounting page.

After a resource is deleted, its accounting remains visible. **Forget archived usage** permanently removes only that deleted resource's ledger, policy and history. The server rejects this operation for a resource still present in inventory.

## Retained history and limits

Retention is optional: off, 24 hours, 7 days or 30 days in the UI. Each resource keeps the latest **288 actual samples**, subject to that maximum age. This is a rolling sample cap, not a promise of full coverage for the selected duration. At a 60-second interval, 288 samples cover approximately 4.8 hours; use a longer interval for a longer span. Reset starts a new chart; completed cycles retain summaries rather than full historical charts. Missing collection periods are not backfilled.

The ledger permits at most 128 entries in each bounded resource map; a collection-capacity error leaves existing counters intact until the selection/archive is reduced. Limits also include 288 samples per history and 12 cycle summaries per resource. The persisted JSON has a 16 MiB read limit and invalid baselines/IDs fail closed. Expired chart samples are filtered when read and pruned on the next write/startup. Turning history off removes retained chart samples when settings are saved; completed cycle summaries and lifetime totals remain.

The browser fetches a compact summary and only the selected resource's history. Mutation jobs retain small receipts, not complete histories. The Traffic page polls summaries only while collection is enabled and the page is visible, no faster than every 30 seconds. No separate database, daemon or sampling service is added. The existing broker does no inventory/collection work while collection is disabled.

## What the numbers mean

- Received/sent are from this server's perspective, not necessarily a VPN client's upload/download direction.
- Port counters count network bytes and can include headers and retransmissions. GRE interface counters and forwarded ports may overlap; the UI never sums them into a misleading global total.
- Reverse accounting covers supported public entrance listeners. Shared control/multiplexed destination traffic is not guessed per customer.
- Reloads, reboots, external counter deletion, process crashes, and unobserved interface replacement can leave gaps. Raw-counter decreases are handled, but two kernel/filesystem states cannot be committed atomically. This is operational accounting, not guaranteed billing-grade metering or an exact volume limiter.
- Optional remote Agents can report bounded read-only lifetime/cycle summaries through the Nodes page. Retained histories and remote quota/reset operations remain unavailable. Inventory selection does not enable remote collection. Do not sum identical traffic measured on two Nodes.
- All system-generated display numbers use Latin digits in both languages; Persian labels and RTL layout remain available.

The root-owned ledger is `/var/lib/gre-manager-panel/metrics.json`. Keep backups private: customer references and accounting history can be sensitive. Panel removal deletes this ledger and only the separate `inet gtm_panel_metrics` table, while preserving tunnel/forwarding configuration.
