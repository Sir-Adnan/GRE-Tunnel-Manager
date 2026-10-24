# Phase 7 / v1.3.1 review

> Historical implementation review. Describes its recorded milestone, not current installation instructions. Start with the [current guides](../README.md).

This milestone fixes responsive RTL alignment, adds local configuration workflows and connection profiles, and consolidates the previously unreleased panel milestones into a matched v1.3.1 package. Publication was explicitly authorized by the user after implementation and checks.

## Delivered

- Isolate technical values inline and align their containers to logical start, so ports remain under their headings in RTL. Select connection tables/cards by actual container width, auto-fit a single card and wrap long IPv6 values. Keep native code and charts intentionally LTR.
- Add local per-connection inspection, copy/download, a managed JSON editor for all four forward engines, and supported existing-value native text imports for HAProxy/Realm. Review is read-only; apply reuses the same revision-checked, full-state Bash transaction, preflight, snapshots and recovery. There is no second native-override source of truth.
- Show recognized GRE commands and redacted FRP/rathole TOML. These resource views are read-only. Neither arbitrary host files nor unknown native/executable directives are exposed. Kernel previews are single-connection excerpts, not complete live rulesets.
- Embed 23 bilingual profiles covering all engine families. They fill drafts only; existing connections are not migrated. HAProxy adds optional bounded FIN/tunnel/retry fields with unchanged absent-key behavior. Preserve a selected profile's algorithm when adding a second target.
- Omit UI profile catalogs from remote inventory so presentation copy does not change Node revisions or increase report payloads.
- Update English/Persian quick-start guides, technical documentation, release notes and synchronized version constants. Preserve frozen legacy scripts, instruction files and the selected Nettinx source palette.

## Evidence

- Generated Bash/whitespace checks and modern-module/installer ShellCheck pass.
- All 117 Python tests pass on Linux with a matching built executable supplied for PTY checks.
- Go race tests and vet pass, including actual Bash profile rendering, optional native HAProxy validation, stale/replayed edits, unknown/executable configuration rejection, Realm legacy-option upgrade, identity restrictions, secret redaction, bounded non-symlink reads, HTTP session/CSRF checks and read-only Agent rejection.
- Frontend clean installation, production build, lint/formatting and six unit tests pass. No runtime editor dependency was added.
- Isolated namespaces pass real forwarding/relay/GRE checks, including HAProxy with the new VPN timeout/retry settings. These do not touch the host network ruleset.
- Browser matrix passes 172 layout states and 28 explicit port/header geometry checks, with no page overflow or application console errors/warnings. Coverage includes Persian/English, dark/light, widths 320–1920, long IPv6 values, single/multiple records, the main pages and editor viewport bounds.
- A separate browser flow saves native HAProxy and managed kernel-forward JSON through the actual demo API and verifies the resulting data. It also checks HAProxy affinity values/algorithm preservation, GRE MTU and FRP QUIC profile selection. Demo changes are simulated, never host-network writes.

Screenshots/logs are ignored local review artifacts under `output/playwright/` and `.work/`. Public two-server deployment, real systemd/reboot behavior and sustained load remain operator verification. No performance benchmark or universal latency/RAM claim is made.

## Boundaries

The editor applies to local managed forward records. Generic remote configuration editing, direct GRE/reverse file writes, unrestricted raw iptables/nftables editing, arbitrary native extensions and operator-global `/etc/haproxy/haproxy.cfg` management are outside this release. Use the dedicated forms/lifecycle tools for resources not editable here. Remote accounting stays read-only; local quotas stay advisory.

See [configuration editing](../CONFIGURATION-EDITOR.md), [connection profiles](../CONNECTION-PROFILES.md), [release notes](../../panel/RELEASE.md) and [roadmap](../ROADMAP.md).
