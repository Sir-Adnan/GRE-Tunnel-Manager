# Phase 3 delivery review

## Delivered scope

Optional, secure **read-only Node inventory** is implemented in source. A panel can run on an entrance, destination or separate management server. Its own local Node is always available without enrollment. Remote Agents are optional and initiate outbound connections; no remote Agent listener is installed.

The normal tunnel pages and privileged write broker remain local. There is no remote job, shell, SSH, file editor or arbitrary native-configuration endpoint. Coordinated GRE/reverse operations remain Phase 4 and require a new instruction from the user.

## Design decisions

| Decision | Reason |
| --- | --- |
| Separate TLS 1.3 Agent listener | Preserve secure control transport independently of browser HTTP/HTTPS |
| One-time ten-minute invitation with authority pin | Authenticate the Controller before transmitting the enrollment secret; avoid trust-on-first-use |
| Agent-generated P-256 key and Controller-assigned node ID | Keep the private key local and prevent a CSR from selecting another node's identity |
| Independent protocol 1 and closed `inventory.read` capability | Decouple application SemVer from wire compatibility and keep remote writes absent |
| Outbound HTTPS reports every 60–70 seconds | Reuse standard Go networking without WebSocket dependencies, queues or a database |
| Memory-only last inventory/contact times | Avoid periodic state writes and stale persisted snapshots after restart |
| Separate metadata and inventory revisions | Protect revocation from stale selections without making routine reporting conflict with it |
| Per-request identity checks, including after body decoding | Enforce revocation on reused TLS connections and while a slow report is in flight |
| Restricted Agent and inventory-only root broker | Keep public networking unprivileged and deny writes before manager execution |
| Service-account key creation during installation | Avoid root writing/chowning identity files inside a service-writable directory |
| Lazy-loaded Nodes UI using existing components | Preserve the palette, font, responsive shell and existing dependency footprint |

The Controller persists only bounded registry/PKI/enrollment metadata with private atomic file replacement and a process-held lock. Agents have a separate identity lease. Certificates renew with bounded serial overlap; CA rotation is explicitly an operator migration. Limits and recovery are documented in [NODES.md](NODES.md).

## Interface

- Bilingual Nodes page with local/remote identity, last contact, observation time, engine/resource counts and read-only detail dialogs.
- Connected, waiting, degraded, offline and revoked states; cached service status is never presented as proof of current tunnel availability.
- Named invitations, hidden terminal enrollment, code clearing on dialog close, explicit HTTP-browser guidance and manual-copy fallback.
- Revision-protected revocation with confirmation; topology, installation, recovery and release-availability help inside the panel.
- Existing Nettinx colors and Vazirmatn preserved. No dependency or theme migration. The prior documented Nettinx contrast exception remains; no new accessibility-conformance claim is made.

## Verification performed

- `python3 tools/build.py --check` and `git diff --check`.
- All **98 Python tests passed on Linux**, including the five new isolated Node installer cases and actual setup/recovery PTY tests using a native Linux binary.
- Windows Python discovery also passed with the expected 17 Linux/PTY skips.
- `go test ./...`, Linux `go test -race ./...` and `go vet ./...` passed.
- New real loopback TLS tests cover multiple identities, pinned enrollment, expired/reused invitations, plaintext-secret non-persistence, foreign authorities, anonymous requests, incompatible protocol/capabilities, canonical bounded inventory, stale/degraded state, certificate overlap/renewal, revocation, state reload, concurrent enrollment, storage failure, connection interruption/retry and cancellation. A slow-body regression verifies that revocation does not wait for report upload and that the revoked report cannot commit.
- The read-only broker regression sends every write category against a nil manager and verifies rejection before execution. Browser API tests cover authenticated local inventory, optional Controller state, same-origin/CSRF enrollment and refusal of remote-node operation fields.
- `npm ci`, frontend production build, lint, formatting, four Node tests and dependency audit passed; audit found no vulnerabilities at validation time.
- ShellCheck passed for all modern modules, `panel-install.sh` and `node-install.sh`.
- The existing isolated Linux namespace suite passed: IPv4/IPv6 nftables, TCP/UDP forwarding, GRE MSS, HAProxy worker reload, Realm PROXY metadata, available reverse engines, optional Go accounting and scoped legacy cleanup preserving unrelated rules.
- Browser checks used a loopback-only fixture with two simulated inventory providers reporting through real TLS, plus the real local-only demo. Persian RTL/English LTR, dark/light, widths 320/360/390/768/1440, invitation generation/clearing, inventory details, help and revocation passed without page-level horizontal overflow or JavaScript page errors in the exercised flow. Computed font was Vazirmatn. These providers did not execute host commands.
- Linux amd64 and arm64 packages were cross-built with checksums. No release asset was uploaded or replaced.

## Operational limits and remaining rollout checks

This is not a live VPS deployment or a resource benchmark. Installer tests use redirected temporary paths and fake accounts/services. Actual distribution/systemd sandbox permissions, service-account terminal input, provider firewalls/NAT, DNS/IPv6 reachability, real two-server reboot behavior and deployment upgrades still need target-host validation. Namespace tests establish dataplane regressions, not public Internet availability.

Inventory limits are deliberate: 64 identities including revoked records, 16 active invitations and 256 KiB per Node report. Reports retain one canonical snapshot; there is no traffic history, durable last-seen database or backlog. The Nodes list returns these bounded snapshots; pagination/separate detail fetch can be added if larger deployments require it. Expired offline identities require re-enrollment. An initial enrollment response lost after commit consumes its invitation and can leave an unused identity to revoke. Filesystem sync/rename does not make installation or multiple hosts transactional.

The published v1.3.0 package is unchanged and predates this feature. Install current source packages through `--package-dir`; publish a new synchronized version/tag later. A new Phase 4 instruction is required before adding remote mutations.
