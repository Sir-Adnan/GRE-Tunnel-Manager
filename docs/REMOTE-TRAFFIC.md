# Remote traffic summaries

The panel supports optional read-only accounting snapshots to **Nodes → View details → Traffic**. They are separate from the panel host's **Traffic usage** page. Use matching current packages; v1.3.0 predates this feature.

## Enable it on an Agent

Install or update the Agent with traffic reporting available:

```bash
sudo bash node-install.sh --agent --traffic --package-dir /path/to/packages
```

Existing identity and explicit paired-operation opt-in are preserved. The installer checks `gtm-panel nodes traffic-version` before stopping a working Agent. Adding `--traffic` does not install nftables, enable sampling, or change forwarding rules. Its broker opens the separate root-owned accounting ledger; the network Agent only reads summaries.

When ready, install nftables if needed for port accounting, then enable collection locally:

```bash
sudo apt-get update && sudo apt-get install -y nftables
sudo gtm-panel nodes traffic --enable --interval 60
```

This deliberately selects **all supported local resources**, with no chart retention. The interval accepts 15–3600 seconds. At most 128 accounting resource keys can be retained. Missing tools, invalid managed state and collection-capacity failures are reported rather than changing unrelated resources. These settings do not create a tunnel or install its engine.

To pause collection and remove the owned accounting table while retaining totals:

```bash
sudo gtm-panel nodes traffic --disable
```

The Agent still sends a paused summary. Re-running installation preserves the `--traffic` service flags and saved enabled/paused state; it never silently enables collection. To restart after a reboot, the saved setting is reconciled by the existing Agent broker when enabled. Stopping the Agent/broker is not the same as disabling accounting: installed kernel counters remain until explicitly removed. Disable collection before retiring the Agent.

The panel host needs no Agent or these commands. Use its ordinary **Traffic usage** settings instead. Do not run panel and Agent accounting brokers against the same host/table.

## Read the report

- **Received / Sent:** current cycle bytes from the measured server's perspective.
- **Lifetime recorded:** received and sent lifetime values, displayed separately. They are not an additional combined global total.
- **Last sample:** time supplied by the Agent's local collector. Keep Node clocks synchronized.
- **Report received:** Controller receipt time for the last readable snapshot. A fresh report does not prove a fresh counter sample; check both times.
- **Paused:** collection is disabled; previously recorded totals remain visible.
- **Stale or unavailable:** the report is older than three minutes or collection/read failed. A failed summary read retains the previous successful values and their receipt timestamp.

Reports normally follow successful inventory reports every 60–70 seconds, independent of the sampling interval. Browser refresh reads the latest cached report and does not force a Node scan. The Traffic tab refreshes every 60 seconds only while mounted and the page is visible. Closing/switching the tab stops that timer. Search works by connection name, technical ID or local port.

No report yet can mean reporting was not enabled, the Agent is older, its local broker is unavailable, or no report has arrived since Controller restart. Inventory can continue normally without traffic reporting. A revoked Node's traffic snapshot is removed and no longer returned.

## Transport and compatibility

`POST /v1/traffic` uses the same dedicated TLS 1.3 listener, active per-Node mTLS certificate and revocation checks as inventory. It has its own **traffic protocol 1**, independent of application SemVer, inventory protocol 1 and paired-operation negotiation. It is an additive sideband endpoint: ordinary inventory reports and capability arrays are unchanged. An older Controller rejects this optional endpoint; the Agent logs a traffic warning on state change and continues inventory/paired work. Identity expiry/revocation remains fatal. Upgrade the Controller to receive traffic.

The body is a closed schema, at most 64 KiB and 128 counters. It carries enabled state, interval, collector start, lifetime/cycle bytes, sample/cycle timestamps and a fixed source/failure vocabulary. Invalid IDs, baselines, unknown fields, extra objects and arbitrary error strings are rejected. Agent-supplied clocks do not determine connection freshness.

The Controller keeps only one in-memory snapshot per identity. It does not persist remote history, queue reports, send traffic through itself or aggregate potentially duplicated bytes across servers. A Controller restart clears these snapshots; the Agent's root-owned ledger survives independently. A failure in traffic reporting does not replace inventory or alter paired-job results.

Authenticated browser access uses `GET /api/nodes/traffic?id=NODE_ID`. The normal public-operation API cannot target a remote server. There are no remote configure/reset/quota/history endpoints in this milestone. The optional private Agent broker admits only metrics summary/configuration in addition to its existing inventory and separately enabled pair operations; general lifecycle, reset, customer policy, history, file and shell operations remain rejected. The local CLI requires Linux root; the private broker socket retains its existing `greagent` group boundary.

## Data and ownership

Agent collection reuses the existing accounting engine and the separate `inet gtm_panel_metrics` table. Its ledger is `/var/lib/gre-manager-agent-traffic/metrics.json`, root-owned, with mode 600 in a mode-700 directory. Local setting changes use the broker mutex and existing accounting recovery path. Customer labels, quotas, history, raw counter baselines, native files, credentials and local error strings are excluded from reports. Inventory already supplies display names separately.

The [local accounting limitations](TRAFFIC-ACCOUNTING.md#what-the-numbers-mean) still apply: overlapping paths, network overhead, restart/crash gaps, asymmetric routing and offloads can affect results. These are operational observations, not billing guarantees or hard volume enforcement. Remote reset/history, scheduled cycles and automatic cutoffs remain separate follow-up work.
