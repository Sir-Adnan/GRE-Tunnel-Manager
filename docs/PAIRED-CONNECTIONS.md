# Connect two servers

The Nodes page can coordinate a new **GRE** or **FRP Reverse** connection across two servers. Choose the panel host and a remote Node, or two remote Nodes. A third management server is optional. Existing engine pages still manage the panel host only.

This feature is included in v1.3.1. Use matching release packages on Controller/Agents; v1.3.0 predates Node support. Source/offline packages can still be installed with `--package-dir`.

## Enable only where needed

1. Install/update the panel and enable its optional Controller using [NODES.md](NODES.md).
2. Install each required engine locally on both selected servers. This workflow never downloads packages or installs engines remotely.
3. Opt remote Agents into the bounded operation contract:

   ```bash
   sudo bash node-install.sh --agent --operations --package-dir /path/to/packages
   ```

   The intended one-command release flow, after compatible packages are published, is:

   ```bash
   bash <(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/node-install.sh) --agent --operations
   ```

4. Enter a fresh hidden invitation only for a new identity; upgrades preserve existing enrollment. Confirm `gtm-panel nodes operations-version` prints `1` on both sides.
5. Refresh Nodes. Select **Connect two servers → New connection**. Read-only or stale Nodes are excluded from the form.

Omitting `--operations` on a fresh Agent keeps its broker read-only. An upgrade preserves a previous explicit opt-in; it must not silently remove a live recovery worker. The panel host uses its existing local root broker and needs no Agent.

Operations-mode installation enables `gre-manager-agent-broker.service` independently at boot, with `StopWhenUnneeded=no`. Keep that service running while unconfirmed changes exist, even if the outbound Agent is stopped. A normal read-only installation retains its previous lifecycle and opens no additional listener.

To retire operation access, finish or recover active jobs first, revoke the Node in the panel, and stop its outbound Agent. Keep the broker running long enough to process outstanding leases. Converting the broker back to read-only or deleting its journal is an explicit local maintenance task after inspecting all receipts; there is no unsafe automatic downgrade switch.

## Guided setup

1. Choose GRE or FRP Reverse and an optional display name. An empty name gets a generated default. Display names are metadata, separate from technical service IDs.
2. Choose two different servers. GRE needs concrete assigned addresses reachable between peers. FRP needs only the entrance's assigned reachable address; its destination service may be on loopback and the destination needs no public listener. The workflow does not infer NAT mapping or alter provider firewall policy.
3. For GRE, choose the shared ID (1–250) and MTU. Entrance maps to the existing `iran` role, destination to `kharej`. Existing keys, interface names and internal addresses remain compatible.
4. For FRP, choose the public and control ports, destination service IP/port, TCP or UDP service protocol, and TCP/WebSocket/QUIC transport. A private shared token and independent service/group name are generated automatically. This preset uses TLS and token authentication; custom CA verification and WSS are excluded.
5. Review both servers and start. Both sides preflight before creation. Entrance applies first, then destination.
6. Test the actual service path yourself, then select **Connection works — keep it** before the earliest displayed lease deadline. Local service startup is not proof of public reachability.

GRE needs protocol 47 permitted between peers. FRP needs its selected control/public ports; QUIC also requires the control UDP port. The workflow does not open these automatically or install default routes, host firewall policies or global tuning.

## State and failures

| State | Meaning |
| --- | --- |
| Checking servers | Validate closed settings, dependencies, assigned address, ports/IDs and current resource/state revision |
| Creating connection | Both checks passed; entrance creates before destination |
| Test and confirm | Both reported creation; each root broker still owns a five-minute confirmation lease |
| Saving confirmation | Explicit administrator confirmation is being recorded on both servers |
| Confirmed on both servers | Both brokers persisted confirmation; tunnels remain independent of the panel |
| Recovering | Request failed, expired or was cancelled; compensate known changes individually |
| Removed / no new resource retained | Each potentially changed side acknowledged safe compensation, or no apply was attempted |
| Inspection required | An interrupted create, missing receipt, changed file, failed cleanup, revoked identity or recovery timeout leaves an uncertain outcome |

Requests expire ten minutes after creation. A broker rejects an expired apply, including after reconnection, and cannot extend an expired preparation using a fresh delivery expiry. Each successfully recorded create has a five-minute lease measured on that server. The Controller starts bounded recovery if a lease expires or a side fails. A recovery attempt has a two-minute acknowledgment window; later retries require the administrator's current job revision.

Broker recovery is independent of the browser, Controller and Agent. It runs on startup and when the next lease becomes due; while idle, it avoids repeated disk scans. A busy broker, stopped service, power failure or failed system operation can delay or prevent compensation. After reboot it retries overdue known leases. This is **not** a hard real-time rollback guarantee or a distributed atomic transaction.

The root receipt is written before create. If the process dies before a verified resource fingerprint is saved, the outcome is unknown and the create is never automatically replayed. Recovery never guesses ownership from a matching name. A recorded fingerprint is compared under the shared Bash lock before confirmation or deletion. An operator edit or an existing dependency can block deletion; inspect the server instead of removing the guard.

Cancellation cannot interrupt an operation already executing in a root broker. Results arriving after cancellation do not revive an expired apply. A failed acknowledgment can be redelivered: the same request ID, stage and settings return the existing receipt, rather than a second creation. Keep system clocks synchronized; expiry is checked independently by Controller and broker.

An individual confirmation can be compensated only within the original ten-minute authorization window if the peer failed to confirm. Once that window closes, a committed resource requires local inspection/removal; a fresh rollback expiry cannot revive remote delete authority. The displayed confirmation deadline is bounded by both the root lease and the original job expiry.

## Scope and authorization

- Administrator session, exact Origin and CSRF checks protect browser writes. Job decisions require the current optimistic revision.
- The separate control listener requires active, unexpired, non-revoked mTLS identities on every work request. Only the assigned Node receives its own task and generated FRP token.
- Protocol 1 adds the optional capability `connections.pair.v1`. Existing `inventory.read` Agents remain compatible and cannot pull work. Older Controllers reject this new capability; upgrade the Controller before opting in Agents.
- The Agent remains unprivileged. The operations broker accepts only `node-task` plus inventory/capabilities; it still rejects general service commands, package installation, forwarding CRUD, logs and arbitrary native configuration.
- Root tasks have only prepare/apply/confirm/rollback/status stages and validated GRE/FRP specifications. There is no executable, shell text, generic argv, file path or remote SSH endpoint.
- The local panel's broader API remains local. Rathole key exchange, WSS certificate provisioning, remote forwarding edits and higher-level balancing groups are outside this phase.

## Persistence and limits

Controller `pairs.json` stores up to 32 retained plans and individual results. It contains private FRP tokens, so back it up with `controller.json` under restricted permissions. List APIs return a redacted view, never these tokens or native configuration.

Each root broker stores up to 256 private receipts in `/var/lib/gre-manager-node-operations`, protected by an exclusive process-held lock. Confirmed, rolled-back, failed and unused prepared receipts become eligible for pruning 48 hours after original request expiry. Unresolved outcomes are retained for inspection. Controller successful/rolled-back jobs have the same 48-hour minimum retention, then may be pruned when creating another job; jobs requiring inspection remain. Capacity exhaustion requires local journal inspection/maintenance, not silent eviction of unresolved work. Idempotency is bounded by this retention; IDs must never be reused for a new request.

One active pair job per Node avoids conflicting concurrent orchestration. Different Nodes can have independent jobs. Successful job records are history, not a complete live inventory; refresh Nodes or inspect local engine pages for current service state. An administrator can still change resources locally after confirmation.

Enabled Agents pull one task every five to six seconds with bounded failure backoff. Inventory remains on the 60–70 second cadence; only the latest report is retained. The browser polls pair status every two seconds only while it has active jobs and is mounted. These are control messages, not tunnel data or traffic sampling.

## Recovery checklist

Inspect `systemctl status gre-manager-agent-broker gre-manager-agent` and their journals on the affected server. Verify the exact service/interface/config paths shown for each side, network reachability, clock, engine availability and any manual edits. Root receipts contain secrets; do not paste them into issues or browser logs.

**Retry safe recovery** can redeliver compensation when a Node reconnects and its root receipt still proves ownership. An interrupted create without a saved fingerprint cannot be recovered automatically. Inspect and remove any verified owned resource through existing local manager controls; do not edit the receipt to force a successful state.

Revocation immediately prevents further work transport. It does not promise deletion of a previously committed resource. Unconfirmed leases can still expire locally, while the Controller records any unacknowledged side as requiring inspection. Never restore an old Controller/root journal while operations are active without reconciling the actual server state.
