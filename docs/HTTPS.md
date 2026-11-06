# Panel HTTPS and automatic certificate renewal

Quick setup creates a **self-signed certificate valid for one year**, covering the chosen IP/domain. It encrypts the connection but does not obtain a publicly trusted certificate or renew it. Verify its SHA-256 fingerprint through SSH before accepting it.

For trusted HTTPS, use an external ACME client such as Certbot or acme.sh. The client issues and renews; the panel validates a private copy and reloads its public HTTPS process. The panel does not open challenge ports, run an ACME daemon or store DNS-provider/account credentials.

## Install an issued certificate

Update the executable and installer-owned service unit together: the unit needs `ExecReload=/bin/kill -HUP $MAINPID`. Replace the example domain with the public host used to open the panel.

```bash
sudo gtm-panel certificate install \
  --cert /etc/letsencrypt/live/panel.example.com/fullchain.pem \
  --key /etc/letsencrypt/live/panel.example.com/privkey.pem \
  --host panel.example.com
```

This local command requires Linux root and shares the installer lock. It accepts the ACME client's regular symlinked generations and checks key matching, hostname/IP SAN, validity, server usage, supplied chain signatures/order and key sizes. Inputs and the combined bundle are bounded to 1 MiB. Private-CA certificates are accepted with an explicit trust indicator; server trust does not prove every browser's trust settings.

The managed copy is `/etc/gre-manager-panel/https.pem`, one atomically replaced certificate/key bundle, root:grepanel mode 640. Both TLS paths in the configuration refer to it. The public process needs no access to the ACME account directory. Initial self-signed files remain; removal deletes only owned copies, never the original ACME source.

For an HTTP installation, add **`--enable-https`** to the first command. It switches protocol and restarts only the public panel; sign in again at its HTTPS address. Normal HTTPS renewals use reload, retaining sessions and established connections. Tunnels and the broker continue independently. `--reload=false` stages a certificate for separate activation.

## Certbot deploy hook

Issue a certificate with the challenge method appropriate to the host. HTTP-01 needs the public challenge port; DNS-01 needs appropriately scoped provider access. Existing tunnel listeners and firewall policy are not changed implicitly. This guide connects an existing certificate and does not install or select a challenge plugin.

Create a root-owned mode-700 executable at `/etc/letsencrypt/renewal-hooks/deploy/gtm-panel`, replacing the lineage/domain:

```sh
#!/bin/sh
set -eu
[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/panel.example.com ] || exit 0
/usr/local/bin/gtm-panel certificate install \
  --cert "$RENEWED_LINEAGE/fullchain.pem" \
  --key "$RENEWED_LINEAGE/privkey.pem" \
  --host panel.example.com
```

Certbot supplies `RENEWED_LINEAGE` after renewal. Keep its existing systemd timer/cron job enabled. Inspect `certbot renew --dry-run` and use its documented deploy-hook testing options to test the hook. A different certificate lineage leaves the panel untouched. The installer does not replace the client's renewal schedule.

## acme.sh install hook

After issuance, use **install-cert** rather than the client's internal account files. Create an operator-owned mode-700 directory such as `/etc/gtm-acme-source` and use the client's actual executable path:

```bash
sudo /root/.acme.sh/acme.sh --install-cert -d panel.example.com \
  --key-file /etc/gtm-acme-source/key.pem \
  --fullchain-file /etc/gtm-acme-source/fullchain.pem \
  --reloadcmd '/usr/local/bin/gtm-panel certificate install --cert /etc/gtm-acme-source/fullchain.pem --key /etc/gtm-acme-source/key.pem --host panel.example.com'
```

Add `--ecc` when required by that certificate's client configuration. Keep keys private. acme.sh retains the install paths and reload command; keep its renewal job enabled. Panel removal leaves operator-owned sources and external hooks in place, so retire its hook explicitly when removing the panel.

## Status and failure handling

- **Settings → Security & access → Panel connection security** reports the certificate actually loaded: host, issuer, fingerprint, expiry and last load time. Expiry within seven days is highlighted. PEM/private keys never reach the browser.
- `sudo gtm-panel certificate status` checks the configured **on-disk** files and prints public metadata as JSON. After a failed reload, this can differ from the still-loaded certificate; check both.
- `sudo systemctl reload gre-manager-panel` rereads the known configuration's TLS paths. Invalid renewal keeps the previous in-memory certificate and records a sanitized error. The authenticated **Reload certificate** button uses the same validation, with no caller-supplied path or privileged command.
- Checked CLI activation failure attempts to restore the previous bundle/configuration and reactivate it. Recovery failure is reported. This is not a power-loss-atomic filesystem/systemd transaction. Inspect public-service and ACME-client logs when fingerprints differ.
- Listener/protocol changes require restart. Do not weaken key permissions to make renewal work.

The panel accepts IP SANs as well as DNS SANs. Public IP issuance depends on issuer/client support and validation. Let’s Encrypt offers short-lived IP certificates; use a compatible ACME client and reliable renewal rather than assuming a domain certificate's lifetime.

Local tests cover invalid pairs/hosts/expiry, bounded files, failed reload retention, concurrent reads, actual TLS handshakes before/after renewal, HTTP authentication/CSRF and publication rollback. Live issuance, DNS/provider challenges, unattended VPS renewal and actual systemd reload remain deployment checks.

References: [Certbot renewal](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates), [acme.sh installation](https://github.com/acmesh-official/acme.sh#3-install-the-cert-to-apachenginx-etc), [Let’s Encrypt IP certificates](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/).

## Domain and address changes

The installer's HTTPS choice creates a self-signed certificate; it does not enroll a domain/IP with an ACME issuer. Public-address discovery runs during setup and read-only host information may refresh later, but it never rewrites the configured public host, certificate SANs, DNS provider records or saved tunnel endpoints. The web panel displays the configured host and has no domain-edit endpoint. For a new domain/IP, update its DNS as needed, obtain the matching certificate externally, then run the documented `certificate install --host NEW_HOST` command with its validated files. An all-address listener follows assigned local addresses; a listener bound to a particular old IP requires a deliberate configuration change and public-service restart. Tunnel endpoints require their own reviewed update.
