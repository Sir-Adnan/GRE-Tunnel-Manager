# Phase 4 review

## Delivered scope

Optional leased GRE/FRP creation now coordinates two selected Nodes, with the panel host optionally serving as either side. Read-only enrollment remains the default. Existing tunnel pages and general operations remain local; this phase adds no arbitrary remote administration.

The Controller persists bounded plans and per-side results, checks Node metadata revisions and explicit capabilities, preflights both sides, applies entrance before destination, and exposes confirmation/recovery separately. Expired or cancelled work does not become a successful job. Browser refresh/restart cannot erase durable operation state.

The root broker persists a receipt before create, refuses blind replay after interruption, checks preparation revisions under the Bash manager lock, and verifies exact resource fingerprints before confirmation/compensation. Five-minute confirmation leases recover independently of the Agent. Missing fingerprints, changed resources and unacknowledged recovery remain visible as uncertain outcomes. This is not a distributed transaction.

## Design boundaries

- Reuse the existing Bash renderers, resource names, locks and removal guards; preserve unrelated state and the GRE wire contract.
- Negotiate `connections.pair.v1` separately from protocol-1 inventory. Agent installation requires explicit `--operations`; readonly Agents retain their previous behavior.
- Keep public HTTP and outbound Agent unprivileged. Add only the closed `node-task` action to an opted-in Agent broker, never its general local operation API.
- Store private FRP tokens only in restricted plan/receipt/native files. Browser responses and logs contain bounded state metadata instead of command output.
- Separate the bilingual setup/review form from job progress/actions. Preserve existing shadcn/Radix composition, Nettinx colors and Vazirmatn; support HTTP-compatible cryptographic request IDs.
- Keep resource measurement outside this phase. No benchmarking, new engine downloads, database, Node runtime or additional inbound Agent listener is introduced.

## Verification

Executed locally:

- Frontend `npm ci`, production build, lint, formatting, all four Node tests and dependency audit (zero vulnerabilities). The build retains Vite's advisory for a roughly 506 kB main chunk; no runtime resource benchmark is claimed.
- Go tests on Windows, plus Linux `go test -race ./...` and `go vet ./...`.
- Full Linux Python suite, generated Bash consistency, modern-module/installer ShellCheck and Git whitespace checks.
- Real private TLS enrollment/work transport and broker receipt tests: replay, stale preparation/decision revisions, expiry, interrupted create, Controller restart, lost acknowledgments, revocation, capability authorization, redaction and failed persistence.
- Browser smoke checks at 320, 390, 768 and 1440 pixels in Persian/English and dark/light modes: 16 combinations, no document overflow, visible form actions and no browser errors. GRE remote-to-remote and FRP local-to-remote creation/confirmation used real Controller/Agent transport with simulated system-operation providers.
- Isolated network namespace suite, including real paired GRE TCP/UDP and FRP TCP startup/removal, fingerprint guards, optional accounting, existing forwarding/MSS and available relay/reverse-engine checks. No production interface or host firewall was used.
- Current-source Linux amd64/arm64 package builds and matching checksums; no archive is published.

## Remaining deployment checks

No live VPS or production systemd service was deployed. Namespace tests replace systemd with a constrained unit runner, and installer tests use fake accounts/services. Verify real two-server setup, systemd shutdown/reboot ordering, address/NAT/provider firewall behavior, long disconnections and recovery on disposable servers before rollout.

Automatic rollback requires a running broker and a saved fingerprint. Storage/process failures can leave an uncertain create; manual inspection is intentional. Confirmed resources are independent of panel availability. Retention/capacity, expiry, CA lifecycle and unsupported pairing engines are documented in [PAIRED-CONNECTIONS.md](PAIRED-CONNECTIONS.md).

Published v1.3.0 remains unchanged. Use packages built from current source with `--package-dir`; no release/tag was replaced. Phase 5 has not started and requires a separate user instruction.
