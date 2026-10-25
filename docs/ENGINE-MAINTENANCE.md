# Engine versions and updates

Open **Tunnel engines → Check versions**. This is an on-demand check, cached for five minutes; it does not install anything or add a background updater.

| Engine | Version source | Update policy |
| --- | --- | --- |
| HAProxy, iptables, nftables | Candidate in the server's configured APT metadata | Explicit, single-package upgrade to the reviewed candidate; no new repository or PPA |
| Realm, FRP, rathole | Stable release from the project's official GitHub API | Only a newer release already verified and checksum-pinned by this manager can be installed |

The latest upstream release and the manager's verified version are deliberately separate. A newer upstream version is not automatically safe for the current renderer, build features or remote peer. No downgrade is offered. GitHub failures/rate limits remain visible; they do not become a false “up to date” result. Distribution candidates reflect the last successful APT metadata refresh, not a live upstream release comparison. Refresh package metadata using the server's normal maintenance procedure when necessary.

## Applying an update

1. Create a backup and keep an independent management connection.
2. Check versions and select **Update engine** for one engine.
3. Read the current/target version and confirm. Changed package metadata or installed versions require a new check.
4. Verify services and connectivity. The manager preserves configuration and does not restart its binary-based tunnels automatically. Existing processes may keep their old binary until explicitly restarted; distribution maintainer scripts can affect services according to local package policy.

Pinned downloads use the existing official release URLs and SHA-256 pins. New binaries are staged before replacement. Prior `/usr/local/bin` binaries are retained under `/etc/gre-manager/engine-backups/update.*`, mode 700 on the containing directory. A failed multi-binary publication attempts to restore every binary already replaced and reports recovery failures. Partial FRP client/server publications must be inspected before restart. Externally managed binary paths are refused rather than overwritten. Operating-system package upgrades are not an atomic manager snapshot and cannot be rolled back by restoring connection state.

FRP requires matching client/server releases. Update peers deliberately and check them before reconnecting production traffic. This page maintains the local server only; it does not silently upgrade remote Nodes.

The public API accepts an engine ID and checked revision, never a release URL, package name, executable path or arbitrary version. The private broker runs fixed operations; read-only Agent brokers reject maintenance operations. Request bodies and configuration contents are excluded from the audit log.

See [Engine capabilities](ENGINE-CAPABILITIES.md), [Configuration editor](CONFIGURATION-EDITOR.md) and [Backup and restore](BACKUP-RESTORE.md).
