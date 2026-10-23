<div align="center">

# GRE Tunnel Manager

**Connect servers. Forward ports. Manage it your way.**

GRE · iptables · nftables · HAProxy · Realm · FRP · rathole

[![Release](https://img.shields.io/github/v/release/Sir-Adnan/GRE-Tunnel-Manager?style=flat-square)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/releases)
[![Checks](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml/badge.svg)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml)

English · [فارسی](README.fa.md)

[Get started](#get-started) · [Web panel](#web-panel) · [Guides](docs/README.md) · [Changelog](docs/CHANGELOG.md)

</div>

Manage tunnels and TCP/UDP forwarding from a straightforward Bash menu or an optional web panel. Use a direct forward, connect servers with GRE first, or choose a reverse tunnel. Each engine has its own setup and management menu.

## Get started

On a **Debian/Ubuntu server with systemd**, run:

```bash
curl -fsSL --ipv4 https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh -o gre.sh && sudo bash gre.sh
```

Logged in as root? Omit `sudo`. Run `sudo bash gre.sh` again from the same folder whenever you need the menu. If curl is missing, install it with `sudo apt-get update && sudo apt-get install -y curl` first. Remove `--ipv4` on an IPv6-only server.

Choose **GRE Tunnel**, **Port Forwarding**, **HAProxy**, **Realm** or **Reverse Tunnel**. For a forward, enter the local port, destination IP and destination port, then review before applying. Names are optional. Several ports, such as `443,8443` or `8000-8003`, can be set up together.

## Pick a connection method

| Method | A good fit for |
| --- | --- |
| **iptables / nftables** | TCP/UDP port forwarding in the Linux kernel; no resident manager process |
| **GRE / ip6gre** | A network link between two servers, with separate forwarding if needed |
| **HAProxy** | TCP relays, health checks, load balancing and failover |
| **Realm** | TCP/UDP relays and weighted destinations |
| **FRP / rathole** | Reverse connections; FRP transports and rathole Noise encryption |

GRE is optional. For WireGuard or AmneziaWG traffic, choose a UDP-capable method; the HAProxy adapter handles TCP. GRE itself does not encrypt traffic and requires IP protocol 47 to pass through the network.

## Web panel

Install the optional panel directly, or choose **8 · Web Panel** in the terminal:

```bash
curl -fsSL --ipv4 https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh -o panel-install.sh && sudo bash panel-install.sh
```

The installer prints the access address. Allow its TCP port in the server/provider firewall, then open it in your browser. For the initial self-signed HTTPS certificate, verify the fingerprint over SSH before trusting it.

The panel supports Persian and English, desktop and mobile, light/dark modes, connection management and optional traffic accounting. It runs as a prebuilt Go executable with the interface embedded; **Node.js, Python, Go compilers and a database server are not required on managed servers**. Tunnel traffic flows through the selected engine, independently of the panel.

**Release availability:** published **v1.3.0** has the original HTTPS setup. The current source also contains quick HTTP/HTTPS installation, Nodes/Agents, coordinated GRE/FRP setup, advanced routing and traffic cycles. These additions need a matching source-built package until the next release is approved. A newer installer does not upgrade the contents of an older binary. [Setup and package details →](docs/WEB-PANEL.md#published-package-versus-current-source)

With a matching source package, quick setup detects the IP and generates credentials:

```bash
sudo bash panel-install.sh --package-dir /path/to/packages --quick
```

## One panel, several servers

Keep everything local, run the panel on an entrance or destination, or use a separate Controller. Other servers can join as optional outbound Agents; the panel host already appears as a local Node. A third server is not required.

Current source supports secure inventory, paired GRE/FRP creation and opt-in read-only traffic summaries. General tunnel editors still operate on the panel host. [Nodes and installation →](docs/NODES.md)

## Useful guides

- [First setup and daily use](docs/USER-GUIDE.md)
- [HAProxy settings](docs/HAPROXY.md) and [TLS / SNI routing](docs/HAPROXY-ROUTING.md)
- [Traffic cycles, resets, labels and quotas](docs/TRAFFIC-ACCOUNTING.md)
- [Remote traffic reports](docs/REMOTE-TRAFFIC.md)
- [Backups and recovery](docs/OPERATIONS.md) · [Panel removal](docs/PANEL-REMOVAL.md)
- [Development](docs/DEVELOPMENT.md) · [Architecture](docs/ARCHITECTURE.md) · [Roadmap](docs/ROADMAP.md)

Allow the required ports and protocols before applying a setup, and test a spare port before moving an active service. Forwarding restore points do not include GRE/reverse peer configurations. The original scripts remain in [legacy](legacy/README.md).
