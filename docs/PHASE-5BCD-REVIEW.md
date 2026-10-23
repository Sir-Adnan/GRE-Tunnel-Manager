# Phase 5B–5D review

## Delivered scope

This source milestone completes the bounded advanced-management profiles authorized by the user after 5A. It also incorporates the subsequent requests for Latin digits, dark labels/icons on orange buttons, destination previews, minimal help, mobile navigation, a visual paired-node selector and source-IP affinity. Application/package version remains 1.3.0; v1.3.1 has not been tagged, published or deployed.

- **HAProxy:** separate routing schema v1 inside record v4; exact-host SNI passthrough, ordered HTTP Host/path-prefix routes, and optional HTTPS termination using root-provisioned PEM IDs. Existing TCP/Reality passthrough remains the default. Native preflight and existing snapshot/recovery apply.
- **Affinity:** optional bounded native source-IP stick table, with entry/expiry limits, off by default. IPv4 and IPv6 paths are packet-tested. State is in memory and resets on worker reload/restart; there are no peer listeners or replicated/disk tables. Source hashing is presented separately from stored affinity.
- **Realm:** pinned 2.9.6 WS, MPTCP and IPv6-only options; transport-feature and kernel checks; correction for official capitalized version output with feature markers. No insecure/native TLS/WSS editor is exposed.
- **Firewall:** manager-owned nftables incremental and fixed-seed source-IP hash selectors for new flows, alongside existing weighted random/source-policy/MSS behavior. Existing iptables scope is unchanged.
- **Names:** a separate, fingerprint-bound GRE/reverse display-name sidecar; locked CAS updates preserve unrelated entries and a previous-file backup. Technical IDs, wire addresses and peer keys stay intact. ASCII display names remain bounded to 40 characters.
- **Accounting:** independent cycle baselines, confirmed reset, lifetime totals, Unicode customer references, direction-specific advisory quotas, recent completed-cycle summaries, optional bounded persisted histories, CSV and scoped forgetting of removed resources. Reset does not alter raw kernel counters or tunnel state. Manual forward disabling uses the existing revision-checked network operation; no automatic cutoff or host conntrack flush is added.
- **Interface:** usage/collection tabs; Latin digits in both locales; LTR technical values; 20-row pagination and mobile connection cards; hover/focus/click/tap destination lists with relative weights; a two-card Node pairing diagram with swap; mobile bottom navigation and full-menu access; contextual help and bounded dialogs; short CSS motion with reduced-motion support.

## Structure and compatibility

Networking validation/rendering remains separate from terminal/web interaction. Routing lives in `model/routing.go` and `src/haproxy_routing.sh`; metadata in `control/metadata.go` and `src/metadata.sh`; traffic cycles/policies/history in `control/traffic_ledger.go`. Frontend Traffic collection drafts, accounting calculations, actions and chart presentation are separate modules. Public HTTP remains unprivileged with a local allowlisted broker/Bash boundary. Remote writes remain leased GRE/FRP pairing only.

Ordinary v1/v2/v3 records retain their formats. Routing adds a separate 14th TSV field and validates the same closed grammar in Go and Bash. Existing v4 routes survive terminal edits and health-option changes. Older managers reject v4 or unknown advanced options; downgrade needs a compatible prior snapshot and matched binaries. The old published v1.3.0 package does not contain these source features. No published asset was replaced.

The browser fetches a compact accounting summary and only the selected resource's archive. Mutation jobs retain small receipts rather than complete histories. Each bounded map has at most 128 resources, history has at most 288 actual samples per resource, and completed cycles have at most 12 entries. Retention is off by default and is a maximum age subject to that sample cap. Collection capacity failures preserve existing counters instead of recreating an oversized ruleset. There is no extra database, Agent transport, graph engine or animation runtime dependency.

## Visual fidelity

Imported Nettinx source JSON and `tokens.css` are unchanged. The user explicitly approved a dark primary-button label/icon correction. `approved-overrides.css` uses the original dark base `#0a0c10` as button ink; `fidelity.accept` allows only the new `button-primary-foreground` companion token. Existing primary fills remain `#ff810a` in light mode and `#ff791a` in dark mode. Other styles fall back to their original primary foreground.

Calculated normal contrast is **7.83:1 light / 7.46:1 dark**, compared with the previous white-label **2.50:1 / 2.62:1**. The existing 80% hover fill composited over the page still gives approximately **9.27:1 / 5.06:1**. Disabled controls are separate inactive states. Sidebar items use existing readable foreground/muted tokens without recoloring source values.

The theme-wide checker still flags five original generic-primary/sidebar token pairs and other pre-existing warnings. Its legacy primary pair does not describe the new button companion token. Registry generation used the documented force option to retain these user-constrained originals; no threshold was weakened and no other recoloring was accepted. This is not a claim that the entire original palette passes WCAG.

## Verification

- Generated `gre.sh` consistency, **115 passing Linux Python tests (no skips)**, modern-module ShellCheck and whitespace checks.
- Go unit tests, Linux race detection, vet and Linux compilation, including reset/restart, stale revision, bounded/expired archives, failed persistence, scoped forgetting, metadata fingerprints and malformed routing.
- Frontend clean dependency installation, build, lint, **6 passing unit tests**, formatting and dependency audit (zero audit findings). No application dependency was added.
- Private network namespaces: existing IPv4/IPv6 forwarding and GRE/FRP/rathole checks where binaries are available, plus HTTP readiness, exact Host/path routing, verified HTTPS termination, SNI passthrough, pinned Realm WS payloads, nftables native selectors and native IPv4/IPv6 source affinity.
- **72 passing browser layout/flow checks with zero page errors, console errors or warnings:** Persian/English, light/dark, widths 320/390/768/1440, compact-height dialogs, destination disclosure, routing/affinity fields, Latin digits, mobile navigation and Node topology. Policy/reset behavior is exercised through the actual demo API; populated charts and remote Node topology use explicitly simulated browser fixtures. These checks do not claim remote deployment.

Final check totals and the commit's CI result are linked in the delivery report. Screenshots are local review artifacts under `output/playwright/`, not production traffic evidence. Browser inspection also caught and corrected HTML `pattern` hyphens for the modern Unicode `v` flag, preventing ignored constraints and console errors.

## Remaining boundaries

No live VPS, provider-firewall, production systemd/reboot or sustained-load deployment was performed. MPTCP option/kernel validation is covered; multipath negotiation and performance across real carriers remain deployment checks. Native package availability may make optional-engine CI cases conditional; the local isolated suite included the pinned Realm binary.

Accounting is operational network-byte accounting, not guaranteed provider billing or an exact volume cutoff. Unobserved crashes/counter/interface replacement can leave gaps. GRE and port measurements may overlap and are not summed. Remote accounting/reset/quotas, automatic hard cutoffs, scheduled cycles and customer accounts are separate future contracts. The paired-node diagram changes presentation; it does not add arbitrary remote shell or general remote engine CRUD.

See [Traffic accounting](TRAFFIC-ACCOUNTING.md), [HAProxy routing](HAPROXY-ROUTING.md), [HAProxy affinity](HAPROXY.md#remember-client-ip-optional), [Realm profiles](REALM-PROFILES.md), [artifacts](ARTIFACTS.md) and [roadmap](ROADMAP.md). Release v1.3.1 requires the user's explicit approval after reviewing these changes and verification evidence.
