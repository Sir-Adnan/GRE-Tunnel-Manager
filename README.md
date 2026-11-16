<div align="center">

# GRE Tunnel Manager

v1.6.0 brings a one-line installer, the `gtm` command, trusted HTTPS with automatic renewal, a two-server wizard, latency history, Node offline alerts and two-factor sign-in. See the [Changelog](docs/CHANGELOG.md).

### Server links. Port forwarding. One place to manage them.

A web panel with a Bash engine — built for TCP/UDP relays, VPN traffic and multi-server setups.

[![Release](https://img.shields.io/github/v/release/Sir-Adnan/GRE-Tunnel-Manager?style=flat-square)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/releases/latest)
[![Checks](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml/badge.svg)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml)

**English** · [فارسی](README.fa.md)

[Install](#install) · [Web panel](#web-panel) · [Documentation](docs/README.md)

</div>

## Install

Run on **Debian or Ubuntu with systemd**:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh | sudo bash
```

A one-minute setup asks for the address, HTTPS, port and login, then prints the panel address. For a one-liner without questions:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh | sudo bash -s -- --domain panel.example.com --port 2053 --yes
```

Open the panel's TCP port in the server/provider firewall and sign in. To link this server to a foreign one, open **Connections → Two servers**: enter the foreign server's IP and the public ports, and the panel creates the GRE tunnel and the forward through it, then lists the values to enter on the other server. For a direct forward use **Connections → New connection**. Afterwards `sudo gtm` shows the status and handles updates, certificates, port, password, logs and removal ([Command line](docs/COMMAND-LINE.md)).

Since v1.6.0 tunnels are managed only in the panel; the terminal menus are gone. Existing tunnels and forwards keep running, and `panel-install.sh` still accepts its earlier options. See the [user guide](docs/USER-GUIDE.md) for the full setup.

## Choose your connection

| Method | Use it for |
| --- | --- |
| **iptables / nftables** | Kernel TCP/UDP forwarding, without a resident manager process |
| **GRE / ip6gre** | A network link between servers, with optional port forwarding over it |
| **HAProxy** | TCP relays, health checks, load balancing and IP affinity |
| **Realm** | TCP/UDP relays with multiple destinations |
| **FRP / rathole** | Reverse connections with managed transport and authentication settings |

GRE is optional and does not encrypt traffic. It requires IP protocol **47** to pass through the network. For WireGuard or AmneziaWG traffic, use a UDP-capable method; the HAProxy adapter handles TCP.

## Web panel

The panel gets a trusted Let's Encrypt certificate for its domain or public IP and renews it automatically. Validation uses TCP port 80 for a few seconds, or Cloudflare DNS for a domain; if it cannot complete, the panel starts with a self-signed certificate and **Settings → Security** (or `sudo gtm https issue`) retries. Settings also offers two-factor sign-in, signed-in sessions and one-click updates. Renewal never interrupts tunnels. `--self-signed` and `--http` are available; see [HTTPS and certificates](docs/HTTPS.md) and the [installation guide](docs/WEB-PANEL.md#installation-and-login).

The panel provides Persian/English layouts, mobile and desktop views, configuration inspection/editing and reviewed imports, setup presets, live server readings and optional per-connection traffic tracking. Its prebuilt Go executable includes the interface: **no Node.js, Python, compiler or database server is needed on managed servers**. Tunnel traffic runs independently of the panel.

HAProxy, Realm and port forwards share one filtered **Connections** page, the overview lists anything that needs attention, and **Ctrl K** jumps to pages, connections and creation forms. Health monitoring keeps uptime, outages and a latency history per connection, and notifications reach Telegram or a webhook when a connection or a Node goes down. **Signal** (dark) is the default look; Graphite, Aurora, Nettinx and Neutral are one click away.

### Manage more than one server

Run the panel on an entrance, destination or separate server. Its own host is already a local Node; other servers can join through optional outbound Agents. A third server is not required.

Agents support inventory, coordinated GRE/FRP setup and optional read-only traffic summaries. General tunnel editors still manage the panel host. [Set up Nodes and Agents →](docs/NODES.md)

## Guides

- **Start and operate:** [User guide](docs/USER-GUIDE.md) · [Backup and restore](docs/BACKUP-RESTORE.md)
- **Configure:** [Setup presets](docs/CONNECTION-PROFILES.md) · [HAProxy](docs/HAPROXY.md) · [Configuration editor](docs/CONFIGURATION-EDITOR.md)
- **Track usage:** [Traffic accounting](docs/TRAFFIC-ACCOUNTING.md) — resets, labels, history and optional quota pauses
- **Maintain:** [Engine updates](docs/ENGINE-MAINTENANCE.md) · [Update](docs/WEB-PANEL.md#updates-and-recovery) · [Remove the panel](docs/PANEL-REMOVAL.md) · [Changelog](docs/CHANGELOG.md)

Quota pauses are opt-in and sampled; traffic can exceed the limit between checks.

Open the required ports/protocols before applying. Test a spare port before replacing an active service. Forwarding restore points do not include GRE/reverse peer configurations.
