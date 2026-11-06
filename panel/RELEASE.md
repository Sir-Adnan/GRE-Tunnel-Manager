# GRE Tunnel Manager v1.5.2

This release fixes nftables tunnel creation, DNS application/retry, panel removal and recovery reliability, and improves the mobile management workspace.

## Fixes and recovery

- Use the non-keyword `gtm_mss` nftables chain so preflight accepts MSS rules.
- Initialize boot helpers for port ranges/multiple DNS answers; validate refreshed destinations, prevent loops, retry failed reconciliation and apply domain policy changes immediately.
- Reset inherited systemd-resolved global lists, verify activation where supported and recover previous DNS files when application fails. The UI distinguishes active/configured servers from a local resolver stub.
- Remove current panel state, scheduled snapshots and strictly recognized interrupted private writes, including `.panel-1130669761`. Unknown files/links, pending Safe Apply and active optimization watches remain protected.
- Bind Safe Apply to its exact restore receipt, order new restore points monotonically and retain failed rollback for bounded automatic and explicit manual retry.
- Preserve per-domain DNS policies in portable recovery; accept older archives, exclude domain names from IP migration and restore imported connections paused.

## HTTPS with external renewal

Certbot/acme.sh manages issuance and renewal. The panel validates the certificate/key, host SANs, validity and key strength; publishes a private bundle; and reloads it without interrupting established connections. Invalid reload retains the last valid in-memory certificate. Settings shows issuer, fingerprint and expiry; HTTP-to-HTTPS conversion is explicit.

The installer's HTTPS option creates a self-signed certificate. It does **not** obtain a public certificate automatically or silently rewrite a configured domain/IP. See [HTTPS setup, renewal hooks and address changes](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/v1.5.2/docs/HTTPS.md).

## Interface

- Four Settings tabs: Security & access, Appearance, Notifications and Metrics; direct links, browser history and retained in-memory drafts.
- Destination editing gives addresses full width on phones, aligns port/share fields and keeps ordering/delete controls separate. Phone cards use dedicated listener/destination rows and avoid splitting port digits.
- Compact phone step navigation and summaries, stable label alignment, optional DNS help available by hover, keyboard or tap; important errors stay visible.
- Signal remains the default; selectable palettes, Persian RTL/English LTR, Latin digits and reduced motion are preserved.

## Upgrade

Update the terminal script and run the current panel installer to load the matching **v1.5.2** executable/helper, then refresh the browser. Credentials, certificates and managed configuration are retained. Old cached installers do not gain the new removal manifest. Linux amd64/arm64 packages include the embedded UI, Bash helper and dependency notices; verify `SHA256SUMS`. Managed servers need no development tools.

Local verification covers Python, frontend build/lint/tests, Go race/vet, ShellCheck, isolated networking/component publication and both UI locales across phone/tablet/desktop widths. The arm64 package is cross-built. Live CA issuance/renewal, physical phones, VPS reboot and DHCP/provider-specific resolver behavior remain deployment checks.
