# GRE Tunnel Manager v1.3.1

This release brings the completed installation, Node/Agent, advanced management and interface milestones into one matched package.

- Fix RTL port/value alignment and choose management tables/cards by available content width. Improve compact dashboards, mobile forms, destination disclosure, Latin numerals and bilingual typography while preserving Nettinx fills.
- Add 23 opt-in connection profiles across HAProxy, Realm, kernel forwarding, GRE, FRP and rathole. HAProxy profiles include long-lived VPN/Reality, bounded IP affinity, primary/backup and small-server choices, with optional FIN/tunnel/retry controls.
- Add per-connection configuration inspection, copy/download, managed JSON editing and supported HAProxy/Realm native-text imports. Review is read-only; apply uses existing revisions, full-state locking, native checks where available, snapshots and recovery. GRE/reverse configuration views remain read-only and reverse secrets are masked. Arbitrary file paths, executable directives and unrestricted native overrides are not exposed.
- Include quick/custom setup, automatic address discovery, selected/random ports and explicit HTTP/HTTPS. HTTPS remains the default. Existing credentials, certificates and protocol settings are preserved on upgrade.
- Include optional outbound mTLS Agents, local Node support, leased paired GRE/FRP setup and optional read-only remote traffic summaries. A separate management server is not required. Remote generic configuration/accounting writes are outside this release.
- Include bounded HAProxy TLS/SNI/HTTP routing, Realm WS/MPTCP/IPv6-only profiles, nftables selection methods and independent display names.
- Include local traffic cycles, resets, labels, advisory quotas, bounded history and CSV export. Quotas do not impose automatic hard cutoffs; accounting is operational rather than billing-grade.

Linux amd64/arm64 archives contain the Go executable, embedded built interface and matching Bash helper. Managed servers need no Node.js, Python, Go compiler, Docker or database server. Verify the matching `SHA256SUMS`.

Upgrade with the current installer, then refresh the browser to load the new embedded interface. The old v1.3.0 assets are unchanged. Retain private configuration/identity backups; newer state/options may require matching prior snapshots for downgrade. Controller/Agent identities and explicit operation/traffic opt-ins are preserved. Protocol checks: setup 2, inventory 1, paired operations 1, traffic 1, panel removal 1.

Verification covers automated Bash/Python, frontend, Go race/vet, real isolated networking/native configuration checks, and responsive browser flows. Public two-server connectivity, provider firewalls, real systemd/reboots and sustained load remain deployment checks; no throughput/latency/resource benchmark is claimed.
