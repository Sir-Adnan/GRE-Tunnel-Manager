# Reliability and interface improvements

This work follows the v1.5.1 review and reported production failures. Implementation stays in the shared engine. These changes ship in v1.5.2; deployment remains a separate operator action.

## Current status

All four phases below are implemented in the v1.5.2 source. Local validation passed: 171 Python tests (including matching-binary PTY tests), 63 frontend tests, clean frontend installation/build/lint, Go race tests and vet, modern ShellCheck, isolated network/component-publication tests and the isolated established-flow quota test. Generated script and whitespace checks passed. Both Linux package architectures were built with checksums and the exact matching Bash helper.

Browser checks covered English/Persian, 320/360/390/412/430/768/1024/1440 px layouts, certificate metadata fixtures, advanced-field focus, simulated DNS apply/restore and a downloaded/encrypted Demo backup restored to an empty Demo with all four records paused. Actual TLS handshakes and HTTP reload signals were tested separately in Go. Demo results are not real-server network evidence.

Remaining rollout checks: real-VPS systemd/reboot ordering, actual DHCP/systemd-resolved integration, live CA issuance and unattended Certbot/acme.sh renewal. No production server was deployed. Published package availability is recorded on the GitHub Releases page.

## Phase 1 — Restore ordinary operations

- Use the non-keyword nftables MSS identifier `gtm_mss` without changing saved records.
- Make server DNS changes replace inherited resolver lists, preserve original files, recover failed publication and show the resolver setup accurately.
- Bring panel removal's closed ownership manifest up to date, including bounded scheduled snapshots; retain unknown files and pending recovery guards.

## Phase 2 — Make recovery predictable

- Initialize fresh boot runners completely.
- Validate DNS changes before apply, retain a known-good cache on failure and reconcile policy changes immediately.
- Give each forwarding mutation an exact restore receipt, retain same-second history in creation order, and preserve failed safe-apply recovery for bounded retries.
- Use resolved destinations for distribution statistics and reveal hidden invalid form fields.

## Phase 3 — HTTPS and portable recovery

- Make the current self-signed HTTPS behavior explicit; add certificate visibility and a safe renewal/reload path appropriate to the selected deployment model.
- Verify current and historical backup compatibility, authentication, migration, pause-on-restore and failure recovery.
- Preserve supported DNS policies in portable backups without importing the old server's host resolver configuration.
- Explain the distinct roles of downloaded encrypted backups, local scheduled snapshots and forwarding restore points.

## Phase 4 — Operator experience and documentation

- Keep the existing Signal default and selectable palettes. Use Inter for English, Vazirmatn for Persian and monospaced text only for addresses, commands and identifiers.
- Strengthen the connection, DNS, backup and HTTPS workflows with readable status, explicit scope, actionable errors and responsive layouts.
- Keep Persian RTL, English LTR, Latin display digits, keyboard navigation and reduced motion.
- Run engine, Go, frontend, real browser and isolated networking checks; distinguish these from real-VPS validation.

## Acceptance

Ordinary connection creation, DNS application and panel removal must succeed with current owned artifacts. Failure injection must preserve prior state or report a recoverable partial failure. Existing configurations and backups remain readable. Unknown host resources are never removed. Documentation and changelog describe actual supported behavior and remaining rollout checks.
