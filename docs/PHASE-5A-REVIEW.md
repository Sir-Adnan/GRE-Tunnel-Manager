# Phase 5A review

## Delivered scope

- Informational engine/version capability registry and bounded local version detection with a five-minute cache and executable-change invalidation. FRP reports client/server mismatch; unknown and unverified releases remain explicit.
- HAProxy TCP-connect or plain HTTP readiness on a separate port, with a closed GET path/Host/exact status contract. Existing TCP defaults and data passthrough remain unchanged. Terminal and bilingual web forms share the validated Bash adapter.
- Corrected version-3 Realm option serialization in the Go model. Creation/editing now writes the validated option field and round-trips it without loss.
- Confirmed panel removal through the installer and terminal menu. Closed file manifest, stopped-state journal checks, lease/uncertainty protection, accounting-only nftables removal, partial-failure reporting, and network resource preservation.

## Verification

The accompanying tests cover closed HAProxy fields/injection rejection, separate readiness/data ports, Realm round-trip compatibility, installed version parsing/cache invalidation, Controller retirement refusal, root receipt/lock protection, accounting table scoping, installer cancellation/refusal/recovery and preserved tunnel files.

Validated locally:

- Python suite on Linux: 110 tests, including isolated installer fixtures and actual setup PTY tests, with the current-source Linux binary.
- Go race tests and vet on Linux; Go tests and vet on Windows. Version/retirement tests cover cache invalidation, closed commands, journal leases and scoped counter removal.
- `govulncheck`: zero affected symbols or imported packages. It reports GO-2026-5932 for the unused `golang.org/x/crypto/openpgp` package at module scope; the panel imports bcrypt, not OpenPGP. This is recorded rather than described as a completely clean module scan.
- Frontend install/build/lint/format, four tests and dependency audit (zero findings). Main JS chunk is about 516 kB; Vite's existing advisory remains.
- All modern Bash modules/installers pass ShellCheck; generated-script and whitespace checks pass.
- Private Linux network namespace suite, including native HAProxy 3.2.9 validation and HTTP readiness rejecting a TCP-reachable backend returning 503, restoring traffic at 204, then rejecting it again when unhealthy. Existing kernel forwarding, GRE/FRP and available engine checks also pass.
- Browser checks: 32 combinations across engine details and HAProxy form, Persian/English, light/dark and widths 320/390/768/1440. No horizontal document overflow, visible form actions, isolated LTR technical fields, four simulated creations preserving HTTP options and no console errors/warnings. Screenshots inspected; Vazirmatn and the exact Nettinx palette retained.

Installer tests redirect paths and use fake accounts/services. Browser mutation checks use the explicit demo; native packet checks use private network namespaces. Real systemd/reboot, public two-server rollout, provider firewalls and sustained load remain deployment checks. No production server or release asset is changed by this milestone. Future milestones remain in [ROADMAP.md](ROADMAP.md).

## Limits

This is milestone 5A, not completion of every Phase 5 adapter. TLS/SNI/HTTP routing, additional Realm transports, broader owned firewall profiles, editable GRE/reverse display metadata and persistent traffic history remain pending. Current remote write scope is still leased GRE/FRP pairing. Version profiles are informational and do not replace native validation or peer checks.

HTTP readiness uses plain HTTP on a separate, operator-provided readiness port; it does not terminate or inspect VPN application traffic. Query strings, arbitrary headers/methods, raw send/expect and HTTPS probes are deliberately outside this bounded profile. Existing HAProxy v1/v2 records retain defaults. New optional v2 keys require the updated manager; older managers reject them, so use an appropriate earlier snapshot for downgrade. Unknown/unrelated files block automatic panel removal.

The exact Nettinx palette and existing typography are preserved. Existing palette contrast limits remain. A frontend build may report the existing large main-chunk advisory; this is not a server runtime dependency or resource benchmark.
