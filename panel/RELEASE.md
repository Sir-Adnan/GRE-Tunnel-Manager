Optional Go web panel with Persian/English, RTL/LTR, responsive shadcn/ui, and the original Nettinx theme.

Current source also includes engine/version profiles, separate-port HAProxy HTTP readiness and guarded `panel-install.sh --uninstall`. The installed package must report `gtm-panel uninstall-version` as `1` for automatic removal. Complete Phase 5 milestones and obtain explicit release approval before changing the application/package version or publishing v1.3.1; do not overwrite v1.3.0 assets.

Manage GRE, iptables/nftables forwarding, HAProxy TCP, Realm TCP/UDP, and FRP/rathole reverse connections. Includes staged forms, multiport creation, grouped operations, engine preinstallation, and optional per-port/interface network counters.

The public HTTP/HTTPS process runs as a restricted user and talks to a local privileged broker. Passwords use bcrypt; authenticated writes require a session and CSRF token. Tunnel engines run independently of the panel. Prebuilt Linux amd64/arm64 packages include the matching Bash manager and embedded frontend; no Go, Node, Docker or database is required on servers.

Supported settings are listed in docs/WEB-PANEL.md. This is not an arbitrary native HAProxy/Realm/firewall configuration editor. The user-selected Nettinx palette is preserved, including its documented contrast limitations. Public two-server, reboot and sustained-load validation remain deployment checks.

Quick/custom setup supports automatic IP discovery, selected/random ports, explicit HTTP/HTTPS and generated administrator credentials. HTTPS remains the default. Existing settings and certificates are preserved; user passwords require eight characters within the bcrypt byte limit. The login page and connection help identify unencrypted HTTP.

Node support has a separate `gtm-panel nodes protocol` contract (currently 1). Until a new release is published, `node-install.sh --agent` requires a matching current source archive through `--package-dir`. Do not overwrite old v1.3.0 assets to make that command succeed. Test Controller/Agent upgrades and preserve private identities before publishing a new version.

Paired-operation packages additionally report `gtm-panel nodes operations-version` as `1`. Upgrade the Controller before opting Agents into `--operations`. Preserve `pairs.json` and each root operation journal privately; verify leased recovery through real systemd/reboot checks before publishing. The wire extension remains protocol 1 with an explicit `connections.pair.v1` capability.
