# GRE Tunnel Manager v1.3.3

This release reorganizes the web panel around clearer connection workflows and adds encrypted backups for recovery after a reinstall or a move to a new server.

## Connection workspace

- Place entrance and destination fields side by side on desktop and stack them on mobile. Separate common setup from advanced controls, retain optional names and show a route summary before review.
- Open connection details from the name, inspect all destinations, and jump to configuration or traffic details. Keep edit visible and move secondary actions into a labeled menu.
- Keep page navigation, search, status filters and selected details in shareable hash URLs, with browser back/forward support. Separate Node inventory from coordinated two-server setup.
- Use a compact dashboard and server-information header. Keep addresses copyable in the header and tunnel forms, including on HTTP pages where the Clipboard API is unavailable or blocked.
- Protect changed drafts from accidental dismissal. Report successful writes separately from inventory-refresh failures. Keep long help inside scrollable, viewport-bounded popovers.

## Backup and restore

- Download a password-protected `.gtm-backup` file containing managed iptables/nftables, HAProxy, Realm, recognized GRE and generated FRP/rathole settings. Preserve IDs, display names, allocation counters and reverse-tunnel credentials, including existing Noise keys.
- Optionally include saved traffic totals, cycle baselines, labels, policies and bounded history. Raw operating-system counter samples are re-established on the destination.
- Inspect the backup source, destination and resources, then replace IPs or interface names for a new server. Repeat validation and target-revision checks before applying.
- Restore only to an empty managed installation. Imported forwards, GRE/reverse services and traffic collection stay paused. Start GRE/reverse resources explicitly with **Start & enable at boot**.
- Protect recovery data with AES-256-GCM and a separate password-derived key. Reject damaged files, wrong passwords, unknown schemas, stale reviews and resource conflicts. Stage validated data behind the local broker and shared Bash lock; never import executable service files or arbitrary commands.

The backup is managed configuration, not an OS image. Panel login/sessions, Controller/Agent identities and registries, pairing journals, external certificates, engine binaries, host-wide policy/tuning and legacy scripts are excluded. Back up Nodes separately and re-enroll them after moving the panel. Existing occupied setups cannot be merged automatically. Accounting persistence follows configuration recovery; a partial failure is reported explicitly. See [Backup and restore](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/BACKUP-RESTORE.md).

## Compatibility and upgrade

Saved connection semantics, GRE wire settings, the selected Nettinx palette, local fonts, Persian RTL/English LTR, Latin display digits and reduced-motion support are preserved. Node protocols and opt-in boundaries are unchanged. No extra resident backup service, scheduler or server-side Node.js/Python dependency is introduced.

Run the matching installer to upgrade, then refresh the browser to load the embedded frontend. Existing credentials, certificates and tunnel settings are retained. Linux amd64/arm64 archives include the panel executable, frontend, matching Bash helper and dependency notices; verify `SHA256SUMS`.

Validation covers Bash/Python, modern ShellCheck, clean frontend build/lint/tests, Go race/vet, isolated network traffic and responsive browser workflows. Public VPS connectivity, actual systemd reboot/recovery, native arm64 execution and sustained capacity remain deployment checks. Previous release tags and assets are unchanged.
