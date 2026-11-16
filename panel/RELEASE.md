# GRE Tunnel Manager v1.6.0

The panel is now the only interface: a one-line installer, the `gtm` command, trusted HTTPS with automatic renewal, and browser tools for certificates, updates, two-factor sign-in and linking two servers. Existing tunnels, forwards and saved settings keep working.

## Install and manage

- **One-line install:** `curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh | sudo bash` verifies the release checksum and asks for the address, HTTPS, port and login in about a minute. Every answer is also an option, so `--domain … --port … --yes` installs without questions.
- **`sudo gtm`** shows services, address, certificate, Nodes and updates, and runs `update`, `https`, `port`, `password`, `logs`, `2fa off`, `agent` and `remove`. Updates keep the previous release and restore it if the new one does not start.
- **Trusted HTTPS built in:** Let's Encrypt for a domain or the server's public IP over port 80 (or Cloudflare DNS for domains), renewed automatically by a timer, with a self-signed fallback that never fails the installation.
- **Terminal menus removed:** tunnels and forwards are managed in the panel; `gre.sh` remains its engine. Earlier installer options still work.

## In the panel

- **Tunnel to a foreign server** (Connections → Two servers): enter the foreign server's IP and the public ports; the panel creates the GRE tunnel and the forward through it and lists the values to enter on the other server.
- **Latency history** per monitored connection under Health: average, peak band, jitter and loss over 1 hour to 30 days, from data the monitor already keeps.
- **Node offline notifications** in the panel, Telegram or a webhook when a Node stops reporting and when it returns.
- **Settings → Security:** request, renew or replace the panel certificate; **two-factor sign-in** with an authenticator app and recovery codes; the list of signed-in browsers with sign-out.
- **Settings → Updates:** the installed and latest release, release notes and a one-click update that survives the panel restart it causes.
- **Get started** checklist on the Overview, **Firewall** and **IP addresses** pages (fixes for blocked traffic, access rules, abuse protection, moving everything after an IP change, additional IPs), and a **Check** tab with the live packet path for each connection.
- Server messages appear in Persian or English, English pages use their own typography, and phones get larger touch targets.

## Upgrade

On a server with an earlier release run `sudo gtm update` (v1.6.0 and later), or the one-line installer above, then refresh the browser. Credentials, certificates, connections and Nodes are retained. Notification channels keep their saved event selection; turn on the new Node events under **Settings → Notification channels**. Verify `SHA256SUMS`.

Local verification covers the Python suite, Go race/vet, frontend build/lint/tests, ShellCheck, isolated namespace packet tests and installation, update, rollback, certificate, two-factor and removal runs in a disposable systemd container. A real Let's Encrypt order and renewal on a public server, provider firewalls and reboots remain deployment checks.

Built with Go 1.27.4, which fixes GO-2026-6859 in the standard library's `net/http`. New dependencies: Charm's Huh, Bubble Tea, Bubbles and Lip Gloss (terminal setup) and `rsc.io/qr` (two-factor QR code), with licenses in `LICENSES/GoDependencies.txt`.
