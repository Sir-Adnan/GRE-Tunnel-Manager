# Panel HTTPS and certificates

The panel serves HTTPS from one of three certificate sources:

| Source | Trusted by browsers | Renewal | Set up with |
| --- | --- | --- | --- |
| **Let's Encrypt** (built in, install default) | Yes | Automatic, systemd timer | Installer, **Settings → Security**, or `gtm https issue` |
| **External ACME client** (Certbot, acme.sh) | Yes | The client's own schedule | `gtm-panel certificate install` from its deploy hook |
| **Self-signed** (`--self-signed`, or fallback) | No: compare the fingerprint | None (one year) | Installer, **Settings → Security**, or `gtm https self-signed` |

In the panel, **Settings → Security → Panel connection security** requests a Let's Encrypt certificate over port 80, renews a managed one now or switches to self-signed. The broker runs the same fixed `gtm-panel certificate` commands as root; the browser sends only the address, an optional email and the staging choice. DNS validation needs the Cloudflare token, so it stays on the server.

All certificate commands run as root on the server, share the installer lock and replace the certificate only after the new one validates for the panel's public address. A failure keeps the loaded certificate. Tunnels and the broker are never interrupted; a renewal reloads the public panel without dropping sessions.

## Let's Encrypt, built in

```bash
# Domain that points at this server, or a public IP address
sudo gtm https issue --domain panel.example.com --email ops@example.com
```

- **Domain or public IP.** Without `--domain`, the panel's configured address is used; `sudo gtm https` asks the same questions interactively. IP addresses get Let's Encrypt's six-day `shortlived` certificate automatically; domains get the standard 90-day certificate.
- **Validation over port 80 (default).** The command opens TCP port 80 for the few seconds an order takes. Port 80 must reach this server: allow it in the server and provider firewall, and do not forward or relay port 80 to another host. If another service uses port 80, stop it briefly or use DNS validation.
- **Validation over Cloudflare DNS (domains only).** No port is opened. Create an API token with **Zone → Read** and **Zone → DNS → Edit** for the zone, save it in a root-only file and pass it once:

  ```bash
  sudo gtm https issue --domain panel.example.com --cloudflare-token-file /root/cloudflare.token
  ```

  `CLOUDFLARE_API_TOKEN` in the environment also works (`sudo --preserve-env=CLOUDFLARE_API_TOKEN …`). The token is never accepted as an argument value. The panel keeps a private copy for renewals; the original file can be deleted afterwards.
- **HTTP panel.** `gtm https issue` (like `gtm-panel certificate issue --enable-https`) switches the panel to HTTPS and restarts only its public service. Sign in again at the `https://` address.
- **Testing.** `--staging` uses the Let's Encrypt staging CA (untrusted, generous limits). `gtm-panel certificate issue --directory URL` selects another ACME CA and `--profile NAME` a CA profile.
- **E-mail** is optional and is sent only to the CA as the account contact.

The installer requests the certificate after the panel starts (`--self-signed` and `--http` skip it). A failed order never fails the installation and leaves a self-signed certificate:

```bash
curl -fsSL .../install.sh | sudo bash -s -- --domain panel.example.com --email ops@example.com --yes
curl -fsSL .../install.sh | sudo bash -s -- --yes    # certificate for the detected public IP
curl -fsSL .../install.sh | sudo bash -s -- --domain panel.example.com --cloudflare-token-file /root/cloudflare.token --yes
```

### Renewal

`gre-manager-panel-certificate.timer` runs `gtm-panel certificate renew` every six hours (randomized by up to 45 minutes, caught up after downtime). It does nothing until a certificate was issued, and renews only in the last third of the certificate's lifetime: about 30 days before expiry for domains and about two days before for six-day IP certificates. That leaves several retries before expiry, well inside the CA's rate limits.

```bash
sudo gtm https renew --force                      # renew now
systemctl list-timers gre-manager-panel-certificate.timer
journalctl -u gre-manager-panel-certificate.service
```

If the panel's public address changes, renewal stops with an explanation; run `certificate issue` for the new address.

### Files

| Path | Owner, mode | Contents |
| --- | --- | --- |
| `/etc/gre-manager-panel/https.pem` | root:grepanel 640 | Loaded certificate chain and key (all sources) |
| `/etc/gre-manager-panel/certificate.json` | root:grepanel 640 | Public status: source, host, expiry, next renewal, last error. No keys, tokens or e-mail |
| `/etc/gre-manager-panel/acme/` | root 700 | `account.key`, `settings.json` (renewal recipe), `cloudflare.token`; files 600 |

The public panel process can read the bundle and the status, never the account directory.

## External ACME client

Use an external client for DNS providers other than Cloudflare, or when it already manages the server's certificates. It issues and renews; its deploy hook hands each new certificate to the panel:

```bash
sudo gtm-panel certificate install --cert FULLCHAIN.pem --key PRIVKEY.pem --host panel.example.com
```

`install` checks the key pair, the host/IP name, validity, server usage, chain order and key sizes (inputs up to 1 MiB), copies the files into `https.pem` and reloads the panel. It also turns off built-in renewal, so two clients never compete.

**Certbot** — root-owned mode-700 `/etc/letsencrypt/renewal-hooks/deploy/gtm-panel`:

```sh
#!/bin/sh
set -eu
[ "${RENEWED_LINEAGE:-}" = /etc/letsencrypt/live/panel.example.com ] || exit 0
/usr/local/bin/gtm-panel certificate install --cert "$RENEWED_LINEAGE/fullchain.pem" \
  --key "$RENEWED_LINEAGE/privkey.pem" --host panel.example.com
```

**acme.sh** — install into a root-only directory and reload through the panel:

```bash
sudo /root/.acme.sh/acme.sh --install-cert -d panel.example.com \
  --key-file /etc/gtm-acme-source/key.pem --fullchain-file /etc/gtm-acme-source/fullchain.pem \
  --reloadcmd '/usr/local/bin/gtm-panel certificate install --cert /etc/gtm-acme-source/fullchain.pem --key /etc/gtm-acme-source/key.pem --host panel.example.com'
```

Keep the client's own renewal job enabled. Removing the panel leaves external clients, their files and hooks in place; retire the hook yourself.

## Status and recovery

- **Settings → Security & access** shows the loaded certificate (host, issuer, fingerprint, expiry) and the renewal state. PEM and keys never reach the browser.
- `sudo gtm https status` summarizes the certificate; `--json` (same as `gtm-panel certificate status`) prints the on-disk certificate and the renewal record as JSON. After a failed reload it can differ from the certificate still loaded in memory.
- `sudo systemctl reload gre-manager-panel` (or **Reload certificate** in Settings) rereads `https.pem`; an invalid file keeps the previous certificate.
- `sudo gtm https self-signed` returns to a new self-signed certificate and turns built-in renewal off.
- When activation fails, the command restores the previous bundle and configuration and reactivates them. This is not a power-loss-atomic transaction; compare fingerprints if in doubt.

Local tests cover the full ACME order against Pebble (Let's Encrypt's test CA) for an IP certificate with the short-lived profile, a renewal on the same account and a failed validation; Cloudflare record creation and removal against a fake API; certificate validation, publication rollback and reload. Issuance from the real Let's Encrypt CA, Cloudflare propagation and unattended timer renewal on a VPS remain deployment checks.

References: [Let's Encrypt IP and six-day certificates](https://letsencrypt.org/2026/01/15/6day-and-ip-general-availability/), [Cloudflare API tokens](https://developers.cloudflare.com/fundamentals/api/get-started/create-token/), [Certbot renewal](https://eff-certbot.readthedocs.io/en/stable/using.html#renewing-certificates), [acme.sh](https://github.com/acmesh-official/acme.sh).
