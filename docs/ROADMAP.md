# Web panel development roadmap

Work is phase-gated. Complete one phase, validate it, report evidence and limitations, then wait for the user's explicit instruction before starting the next. Completion does not imply an automatic release or deployment to live servers. Resource benchmarking is outside this roadmap at the user's request.

## Phase 1: Interaction fixes and responsive interface

Status: implemented and validated in the preceding phase.

- Fix Switch/Checkbox state styling against the actual Radix API, including keyboard interaction and partial selection.
- Use the installed Radix/shadcn foundation; adopt the official sidebar composition and Area chart components without migrating to Base UI.
- Redesign traffic usage into full-width settings, per-connection usage and a separate chart. Distinguish draft settings, applied collection state, empty results and failures.
- Show the actual engine separately from internal IDs and accounting sources. HAProxy traffic can be measured by nftables without becoming an nftables forward.
- Provide action tooltips and help that supports hover, focus, click and tap.
- Use Vazirmatn as the application font, locale-aware display numbers, logical RTL alignment and isolated LTR IP/port/code values.
- Add a top-bar light/dark/system selector and responsive mobile forms.
- Expose optional forward/relay names in the normal form, with an automatic default. Restrict creation from dedicated engine pages to that engine.
- Chart only actual samples fetched during the current page visit, bounded to 60 per resource. Do not fabricate history or aggregate overlapping GRE and forward counters.
- Maintain English technical documentation. The UI remains Persian/English; the terminal remains fixed English.

Acceptance: switches visibly toggle and persist after saving; row selection and partial selection work; HAProxy creation retains its engine with an empty name; hover/focus/tap help works; mobile pages have no document-level horizontal overflow; Persian/English and both color modes are checked; project checks pass. This phase adds no remote-control or new networking capability.

## Phase 2: Simple installation and access

Status: implemented and validated in source; Phase 3 follows below. No replacement release was published. See [Phase 2 review](PHASE-2-REVIEW.md) and [installation guide](WEB-PANEL.md#installation-and-login).

- Explicit HTTP or HTTPS on IP, plus domain addresses. HTTPS remains the recommended choice; HTTP clearly identifies its unencrypted transport. Cookie and Origin checks must follow the configured protocol.
- Quick installation with automatic IP detection when omitted, optional/random port and generated administrator credentials, printed once. The installer cannot provision an arbitrary public domain without DNS access.
- Accept user passwords with at least eight characters while enforcing bcrypt's byte limit. Generate stronger random passwords for quick installation. Never put passwords in argv, logs or URLs.
- Preserve existing installations, certificates and credentials; document recovery and detection failures.

Acceptance: fresh installation and upgrade, both browser protocols, login/logout/CSRF, blank IP, failed discovery, occupied port and preservation of existing credentials are covered. Agent control transport remains authenticated and encrypted regardless of browser HTTP selection.

## Phase 3: Versioned Node/Agent contract and secure read-only inventory

Status: implemented in source. See [Node guide](NODES.md) and [Phase 3 review](PHASE-3-REVIEW.md). No replacement release was published; Phase 4 follows below.

- Support local-only installation, Controller with its own local Node, and Controller with multiple remote Nodes. A third server and remote Agent enrollment are optional.
- Define stable node IDs, protocol versions independent of application versions, capability negotiation, revisions and structured failures.
- Use short-lived one-time enrollment, separate per-node identities, mTLS, revocation and automatic leaf-certificate renewal. CA rotation remains an explicit operator migration. Provide a one-command installer without exposing secrets in process arguments.
- Agents initiate outbound HTTPS reports with reconnect/backoff/jitter and no report backlog (only the latest snapshot is retained). Never expose the current privileged Unix broker directly to the Internet.
- Initially provide read-only inventory, last-seen timestamps, stale-state indicators and a distinction between an offline Agent and a stopped tunnel. Include the Controller's local Node in the same list.
- Add in-panel help for roles, installation, topology choices and troubleshooting.

Acceptance: multiple remote Nodes plus a local Node, enrollment/revocation, incompatible versions, interrupted connections and tunnel independence are covered. Remote writes remain disabled.

## Phase 4: Bounded operations and coordinated two-node connections

Status: implemented in source for leased GRE and FRP pairing. See [Paired connections](PAIRED-CONNECTIONS.md) and [Phase 4 review](PHASE-4-REVIEW.md). Wait for the user before Phase 5.

- Allowlisted operations with authorization, unique job IDs, expiry, idempotency and revision checks; no arbitrary shell endpoint.
- Persist Controller jobs and results, and reject expired jobs after reconnection.
- Coordinate GRE and reverse creation by selecting entrance/destination Nodes, preflighting both, applying in a defined order and recording individual outcomes.
- Provide compensating rollback and time-limited confirmation for management-path-sensitive changes. Expose partial application rather than reporting overall success.
- Support multiple entrance/destination connections as independent resources before adding higher-level groups.

Acceptance: successful pairing, one-sided failure, repeated delivery, Controller restart, stale revisions and recovery are covered. Do not claim distributed atomic transactions.

## Phase 5: Engine capabilities and advanced management

Status: milestones 5A–5D implemented in source within the closed profiles below. The user explicitly authorized the remaining milestones together, then approved dark text/icons on orange buttons and Latin digits throughout the panel. See [Phase 5B–5D review](PHASE-5BCD-REVIEW.md). No replacement release was published. Public two-server/systemd/reboot verification remains a deployment check.

This phase is split into reviewable milestones because TLS/routing state, display metadata and retained accounting have different compatibility and recovery requirements:

1. **5A — capability foundation and application readiness:** delivered. Preserve TCP defaults, expose actual adapter limits, validate HTTP checks natively, and add guarded panel removal.
2. **5B — TLS/SNI and bounded HTTP routing:** delivered with separate v4/routing-v1 schema, exact-host rules, operator-owned PEM references and unchanged TCP defaults.
3. **5C — Realm and owned firewall expansion:** delivered for pinned WS, MPTCP and IPv6-only profiles plus nftables incremental/source-IP hash selectors; no raw native directives or Realm TLS/WSS editor.
4. **5D — display metadata and optional traffic retention:** delivered for local display names and accounting cycles, customer labels, advisory quotas, bounded histories, CSV and confirmed manual controls. Remote accounting/Node history aggregation remains a separately scoped future feature.

- Build an engine/version capability matrix before exposing more HAProxy, Realm or firewall settings. Keep simple/advanced modes, presets and native configuration validation.
- HAProxy priorities: richer health checks/failover, then TLS/SNI and bounded HTTP/ACL features with separate tests.
- Realm priorities: supported options for the pinned version, then native transports/MPTCP only after confirming compatibility.
- Expand only manager-owned firewall resources; do not become an unrestricted host ruleset editor.
- Add editable GRE/reverse display names independent of technical IDs, shared service names and keys, with a compatible metadata migration.
- Add optional bounded traffic history/retention, Node/tunnel/port filters and Area charts. Cover resets, lost connectivity and overlapping measurement paths.

Acceptance: each advertised capability has a supported version, generated configuration validation, compatibility/recovery tests and documentation. Do not label a partial adapter as supporting every native engine feature.


### Explicit follow-up scope

Read-only remote traffic summaries are delivered in Phase 6 below. Remote retained history, quota/reset operations, automatic hard volume cutoffs, scheduled billing cycles and customer accounts require separate contracts and tests. They are not implied by local advisory quotas. Realm native TLS/WSS certificate handling, arbitrary HAProxy ACLs and unrestricted firewall editing remain outside the delivered profiles. Release v1.3.1 requires explicit user approval after reviewing the final implementation and verification evidence.

## Phase 6: Multi-server traffic visibility

Status: read-only summary milestone and compact dashboard implemented and validated in source. See [Phase 6 review](PHASE-6-REVIEW.md). No release is implied.

- Add optional traffic protocol 1 independently of inventory/pair negotiation, with existing per-identity mTLS and revocation.
- Keep ordinary Agents inventory-only; require explicit `--traffic` installation and separate local collection enablement. Preserve identity and opt-ins on upgrade.
- Reuse the collector with a root-owned Agent ledger, disabled by default, no chart retention and bounded resource count.
- Present per-connection cycle/lifetime snapshots in responsive, bilingual Node detail tabs; show Controller receipt and Agent sample times separately. Poll only an open visible traffic tab.
- Preserve known values on summary failure, reject malformed/oversized reports, clear revoked snapshots and tolerate older Controllers without breaking inventory.
- Replace oversized dashboard connection cards with a dedicated compact responsive summary; tighten related mobile cards and remove stretching/duplicate promotion content.
- Rewrite English and Persian quick-start READMEs and reconcile outdated capability descriptions. The Persian README is an explicit user-requested exception to English technical documentation.

Acceptance: identity isolation, old inventory compatibility, revoked/expired identities, failure/staleness, payload bounds, privacy projection, restart behavior, installer opt-in preservation and responsive UI are verified. Public server/systemd rollout remains an operator check.

Next milestones remain separately reviewable: remote history/on-demand reads, revision-checked remote reset/configuration, scheduled local cycles, and broader engine profiles. Hard cutoffs need an explicit connection-lifecycle policy; they are not inferred from advisory quotas.
