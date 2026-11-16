# Roadmap

This is a direction for future work, not a promise. The [changelog](CHANGELOG.md) records what shipped, and the [capability matrix](ENGINE-CAPABILITIES.md) describes what each engine adapter supports today. The roadmap as it stood before v1.6.0 is [archived](archive/ROADMAP-1.5.md).

## Available in v1.6.0

- **Setup and administration:** a one-line installer with a short guided setup, the `gtm` command for status, updates, HTTPS, port, password, logs and removal, built-in Let's Encrypt for a domain or IP with automatic renewal, and one-click updates, certificates, two-factor sign-in and a session list in the panel.
- **Connections:** kernel forwards (nftables, iptables) with port ranges and mapping, HAProxy and Realm relays, GRE tunnels and FRP/rathole reverse links in one bilingual panel. A two-server wizard creates a GRE tunnel and the forward through it in one flow. Configuration inspection and editing, reviewed imports, templates, safe apply and drag-and-drop ordering.
- **Health and monitoring:** optional checks with uptime, outages, latency history per connection (one hour to 30 days), weekly reports, failover for balanced kernel forwards, a GRE quality and MTU test, a connection check with the live packet path, guided diagnosis and an opt-in Prometheus endpoint. Notifications go to webhook and Telegram, including Nodes going offline and coming back.
- **Server care:** firewall status with fixes, per-connection access rules and abuse protection, an IP addresses page that moves everything after an IP change, server optimization with automatic undo, maintenance plans, change history with restore, and scheduled encrypted backups.
- **More than one server:** optional Nodes with outbound Agents for inventory, coordinated GRE/FRP creation, readdressing both GRE ends, far-side checks, speed tests and read-only traffic summaries.

## Next

| Priority | Proposed work | Acceptance before shipping |
| --- | --- | --- |
| 1 | Real-server rollout coverage | Two disposable VPSs: reboot, service ordering, provider firewall, a real Let's Encrypt order and renewal, and interrupted-operation recovery under TCP/UDP traffic |
| 2 | Both ends from the two-server wizard | When the foreign server is an online Node, create its GRE end through the paired operation instead of showing values to enter; same rollback and confirmation as paired creation |
| 3 | Off-server backup copies | Scheduled encrypted backups sent to Telegram or a webhook, size-bounded, with secrets never logged and a restore tested from the copy |
| 4 | Sign-in address allowlist | Addresses and networks allowed to sign in, a check that the current browser stays allowed, and `gtm` as the recovery path |
| 5 | Shared reverse-connection lifecycle | Versioned FRP/rathole state, secret references, edit/restore and migration tests; existing instances retained |
| 6 | Bandwidth limits for kernel forwards | Per-connection rate limits in the owned nftables table, measured under load; existing forwards unchanged until opted in |
| 7 | Scheduled local traffic cycles | Explicit timezone and retention policy, restart-safe scheduling and confirmed reset semantics |

Quota pauses stay sampled and opt-in. Byte-exact kernel quota objects, remote quota edits, customer accounts, unrestricted HAProxy ACLs and Realm native TLS/WSS are not planned features.

## Candidate methods

Consider WireGuard server links first, then a separate AmneziaWG adapter when there is a concrete deployment need. GOST chains and GRE-over-UDP may address specific routing or filtering cases. Each needs a versioned contract, an ownership model, peer and MTU validation and recovery tests before it enters the catalog. Forwarding traffic to an existing WireGuard service is already supported and is distinct from provisioning that link.

Keep the data path independent of the panel. Add background work only as an explicit option, and do not infer throughput, latency or memory guarantees from a language or transport choice.

Earlier phased plans and completed reviews are preserved in the [archive](archive/README.md).
