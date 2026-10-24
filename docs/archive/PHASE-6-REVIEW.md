# Phase 6 review

> Historical implementation review. Describes its recorded milestone, not current installation instructions. Start with the [current guides](../README.md).

This milestone delivers optional read-only remote traffic summaries and a more compact dashboard. It also restores a Persian quick-start README at the user's explicit request. Technical guides remain English. Application/package version stays 1.3.0 until a separately approved release; published assets have not been replaced.

## Delivered behavior

- Agents can opt into traffic reporting with `--traffic`. Sampling is a separate explicit local action, off on a fresh installation. Existing identity, paired-operation opt-in and collection state survive upgrades.
- A closed traffic-protocol-1 sideband uses the existing dedicated mTLS listener without changing inventory/pair negotiation. Older Controllers can reject the optional report without stopping ordinary inventory. Identity expiry/revocation remains enforced.
- The Controller retains one bounded memory-only snapshot per Node, with receipt time separate from Agent sample time. Unknown fields, unsupported IDs/sources, invalid baselines and oversized reports fail closed. Failed reads retain known totals; revoked identities lose their traffic snapshot.
- Node detail tabs separate inventory from traffic, showing current-cycle and lifetime receive/send values with search, paused/stale states and local setup guidance. Polling occurs only in the selected, visible Traffic tab.
- The overview uses its own five-row connection summary instead of repeating the full manager's vertical cards. Container queries keep desktop rows compact and place source/destination fields together on mobile. Editing and multi-target disclosure remain available.
- Related mobile management cards use adjacent field/value groups; destination values retain logical alignment and isolated LTR addresses. Short settings/resource cards do not stretch to taller neighbors. Long technical resource IDs wrap. The redundant dashboard promotion panel is removed.
- English, Persian and panel READMEs now emphasize practical setup, requirements and package availability. Persian prose starts with Persian words and uses an RTL wrapper. Outdated adapter descriptions are reconciled with delivered routing/Realm/nftables profiles.

No theme fills, imported Nettinx source tokens, credentials, existing tunnel configurations, frozen legacy scripts or agent instruction files are changed. No additional runtime dependency, database, collector daemon or public listener is introduced. Enabling optional port accounting still requires nftables, using the existing collector.

## Verification

- Generated Bash check and 117 Python tests pass on Linux, with the built Linux executable supplied for setup PTY tests.
- Modern-module/installer ShellCheck and whitespace checks pass.
- Go race tests and vet pass on Linux, including actual localhost mTLS Agent delivery, identity isolation, reused-connection revocation/expiry, bounded/closed reports, privacy projection, failure preservation, Controller restart and optional-endpoint compatibility.
- Frontend clean install, production build, lint, formatting and all six unit tests pass; npm reports zero known dependency vulnerabilities in that install.
- Isolated namespace tests pass, including actual forwarded receive/send counter traffic and preservation of forwarding when the separate accounting table is removed. Existing GRE, relay and routing checks also pass where their pinned tools are available.
- Browser checks cover 48 dashboard/connection/settings combinations, 32 remote-traffic combinations and 16 long-resource-layout combinations. Persian/English, dark/light and viewport widths 320–1920 are included as applicable. No application console warnings/errors or document-level horizontal overflow were observed in the main matrices.
- A normal summary row measures approximately 63 px on the tested wide desktop, 111–112 px at width 390 and 131–132 px at width 320. These are layout observations, not CPU/RAM benchmarks. Extra destinations, long names and remote snapshots are explicitly browser-only fixtures; opening an edit form does not apply it.
- Linux amd64/arm64 source archives build; checksums and matching Bash helper bytes are verified. Traffic, inventory and setup contract probes return 1, 1 and 2 respectively.

Screenshots and execution logs are local ignored review artifacts under `output/playwright/` and `.work/`. They are not live-server deployment evidence.

## Limits and follow-up

The full accounting workspace and its resets, labels, quotas and retained history remain local to the panel host. Remote summaries exclude customer policies, raw baselines, histories, credentials and local error text. They do not aggregate potentially duplicated bytes across GRE/forward paths or across Nodes. The Controller cannot configure/reset remote accounting in this milestone; the protected local Agent broker accepts only the documented accounting summary/configuration extension.

Public VPS connectivity, real systemd installation/upgrades/reboots, carrier behavior and provider firewalls still need deployment verification. No resource benchmark or throughput claim is made. Remote history/mutations, scheduled cycles and hard cutoff policy remain future milestones with separate acceptance criteria. A release or live deployment still requires the user's explicit approval.

See [Remote traffic](../REMOTE-TRAFFIC.md), [local accounting](../TRAFFIC-ACCOUNTING.md), [architecture](../ARCHITECTURE.md) and [roadmap](../ROADMAP.md).
