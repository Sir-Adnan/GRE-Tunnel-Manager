<div align="center">

# GRE Tunnel Manager

### Server links. Port forwarding. One place to manage them.

A Bash manager with an optional web panel — built for TCP/UDP relays, VPN traffic and multi-server setups.

[![Release](https://img.shields.io/github/v/release/Sir-Adnan/GRE-Tunnel-Manager?style=flat-square)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/releases/latest)
[![Checks](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml/badge.svg)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml)

**English** · [فارسی](README.fa.md)

[Install](#install) · [Web panel](#web-panel) · [Documentation](docs/README.md)

</div>

## Install

Run on **Debian or Ubuntu with systemd**:

```bash
curl -fsSL --ipv4 https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh -o gre.sh && sudo bash gre.sh
```

Choose a method, enter the ports and destination, then review and apply. Names are optional; multiple ports such as `443,8443` or `8000-8003` work in one setup. To reopen the menu, run `sudo bash gre.sh` from the same folder.

Already root? Omit `sudo`. On IPv6-only servers, remove `--ipv4`. See the [user guide](docs/USER-GUIDE.md) for the full setup.

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

Install directly, or select **Web Panel** in the terminal menu:

```bash
curl -fsSL --ipv4 https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh -o panel-install.sh && sudo bash panel-install.sh --quick
```

Quick setup detects the IP, chooses a free port and prints the address and generated login once. Allow that TCP port in the server/provider firewall. HTTPS is the default; verify the initial certificate fingerprint over SSH. Custom ports, domains and explicit HTTP are supported in the [installation guide](docs/WEB-PANEL.md#quick-and-custom-setup).

The panel provides Persian/English layouts, mobile and desktop views, configuration inspection/editing, setup presets and optional per-connection traffic tracking. Its prebuilt Go executable includes the interface: **no Node.js, Python, compiler or database server is needed on managed servers**. Tunnel traffic runs independently of the panel.

### Manage more than one server

Run the panel on an entrance, destination or separate server. Its own host is already a local Node; other servers can join through optional outbound Agents. A third server is not required.

Agents support inventory, coordinated GRE/FRP setup and optional read-only traffic summaries. General tunnel editors still manage the panel host. [Set up Nodes and Agents →](docs/NODES.md)

## Guides

- **Start and operate:** [User guide](docs/USER-GUIDE.md) · [Backup and restore](docs/BACKUP-RESTORE.md)
- **Configure:** [Setup presets](docs/CONNECTION-PROFILES.md) · [HAProxy](docs/HAPROXY.md) · [Configuration editor](docs/CONFIGURATION-EDITOR.md)
- **Track usage:** [Traffic accounting](docs/TRAFFIC-ACCOUNTING.md) — resets, labels, history and advisory quotas
- **Maintain:** [Upgrade](docs/WEB-PANEL.md#existing-installations-and-recovery) · [Remove the panel](docs/PANEL-REMOVAL.md) · [Changelog](docs/CHANGELOG.md)

Open the required ports/protocols before applying. Test a spare port before replacing an active service. Forwarding restore points do not include GRE/reverse peer configurations. The original scripts remain in the [legacy archive](legacy/README.md).
