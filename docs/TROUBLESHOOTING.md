# Troubleshooting

**English** · [فارسی](fa/TROUBLESHOOTING.md)

Start with `sudo gtm`: it shows whether the services run, the panel address, the certificate and updates. `sudo gtm logs` shows the recent log.

## The installer shows nothing after "Package verified"

v1.6.0 could stall there under `curl … | sudo bash` on some terminals, before printing anything. Press Ctrl+C (nothing was changed yet) and run the current installer, which shows every step with a progress bar:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"
```

Installing all engines (`--engines`) runs `apt-get` once and downloads Realm, FRP and rathole from GitHub; on a slow mirror this takes a minute or two. The live line shows what is being installed.

## The panel does not open

- **Firewall:** allow the panel's TCP port in the server firewall (UFW) and in the provider's firewall (Hetzner, AWS security group …). The installer does not open firewalls.
- **Address:** `sudo gtm` prints the exact address, including `http://` or `https://` and the port.
- **Service:** if `sudo gtm` shows the panel as stopped, `sudo gtm logs` says why; `sudo bash -c "$(curl …)"` again repairs the installation and keeps its settings.

## The certificate was not issued

The panel then runs with a self-signed certificate, so the browser warns. Common causes:

- Port 80 is closed in a firewall, or another service (nginx, a forward) uses it. Allow it, or stop the service for a minute.
- The domain does not point to this server yet (check with `dig +short panel.example.com`).

Retry with `sudo gtm https issue`, or **Settings → Security → Get trusted certificate**. For a domain behind Cloudflare, use DNS validation; see [HTTPS and certificates](HTTPS.md).

## The browser warns about the certificate

A self-signed certificate is encrypted but not trusted by browsers. Compare the SHA-256 fingerprint from the install summary (or `sudo gtm https`) with the one the browser shows, or get a trusted certificate as above.

## Forgotten password or lost authenticator

```bash
sudo gtm password        # set a new password; every session signs out
sudo gtm 2fa off         # turn two-factor sign-in off
```

To change a password you still know, use **Settings → Security → Sign-in → Change password** in the panel: no SSH, no restart, and only the other browsers are signed out.

## An additional IP disappears after a restart

An address added with `ip address add` lives only until the next restart; connections on it stop afterwards. The **IP addresses** page marks such an address **Temporary**: **Keep after restart** stores it in a small systemd unit that adds it again at every boot. To add a new additional IP, use **IP addresses → Add IP** instead of the command. See [IP addresses](IP-ADDRESSES.md).

## A tunnel or forward does not pass traffic

- Open the connection's **Check** tab: it follows the packet path and names the step that drops it, with a fix.
- The **Firewall** page lists what blocks traffic now (for example a `FORWARD DROP` policy from Docker or UFW) with a **Fix now** button. See [Firewall](FIREWALL.md).
- GRE needs IP protocol 47 between the two servers, also in provider firewalls, and the same tunnel ID on both ends.

## Still stuck

`sudo bash /usr/local/lib/gre-manager/manager.sh --doctor` runs read-only checks. Open an issue with its output and `sudo gtm status --json`. Both contain addresses, so review them before you post.
