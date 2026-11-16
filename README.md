<div align="center">

# GRE Tunnel Manager

### Tunnels, port forwards and relays for your servers — from one clean web panel.

[![Release](https://img.shields.io/github/v/release/Sir-Adnan/GRE-Tunnel-Manager?style=flat-square)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/releases/latest)
[![Checks](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml/badge.svg)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml)

**English** · [فارسی](README.fa.md)

[Install](#install-in-one-minute) · [Features](#why-gre-tunnel-manager) · [Docs](docs/README.md) · [Changelog](docs/CHANGELOG.md)

</div>

## Install in one minute

On Debian or Ubuntu:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"
```

The installer shows each step with a progress bar, asks five short questions (address, HTTPS or HTTP, port, login, engines) and prints your panel address. Open that port in your firewall and sign in.

**No questions — pick a recipe:**

```bash
URL=https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh

# Trusted HTTPS for the server's IP, random port, generated password
sudo bash -c "$(curl -fsSL $URL)" @ --yes

# HTTP with your own port, username and password
sudo bash -c "$(curl -fsSL $URL)" @ --http --port 8080 --user admin --password 'my-long-password' --yes

# HTTPS for your domain
sudo bash -c "$(curl -fsSL $URL)" @ --domain panel.example.com --port 2053 --yes
```

All options, updates and removal: **[Installation guide](docs/INSTALL.md)**.

## Why GRE Tunnel Manager

- **Two servers in one form.** Enter the foreign server's IP and your ports: the panel builds the GRE tunnel and the forward through it, and lists what to enter on the other side.
- **Every method in one place.** iptables and nftables in the kernel, GRE/ip6gre, HAProxy, Realm, FRP and rathole, on one **Connections** page.
- **See problems before users do.** Health checks with uptime and latency history, a packet-path **Check** for each connection, firewall diagnosis with one-click fixes, alerts by Telegram or webhook.
- **Safe by design.** Trusted HTTPS that renews itself, two-factor sign-in, automatic revert for risky firewall changes, encrypted backups, and verified updates that roll back on failure.
- **Light on the server.** One prebuilt Go binary and a Bash engine. Traffic stays in the kernel; the panel can stop without touching a tunnel.
- **Persian and English**, right-to-left and left-to-right, on desktop and phone.

| Method | Best for |
| --- | --- |
| **iptables / nftables** | Fast kernel TCP/UDP forwarding, port ranges, load balancing |
| **GRE / ip6gre** | A private link between two servers (needs IP protocol 47) |
| **HAProxy** | TCP relays with health checks, failover and IP affinity |
| **Realm** | TCP/UDP relays with several destinations |
| **FRP / rathole** | Reverse tunnels when the destination cannot accept connections |

GRE does not encrypt. For WireGuard or other UDP traffic, choose a UDP-capable method.

## After installing

```bash
sudo gtm            # status and a menu: update, HTTPS, port, password, logs, remove
sudo gtm update     # verified update; the previous release returns if anything fails
```

More servers can join as outbound **Nodes**; no third server is needed. [Nodes and Agents →](docs/NODES.md)

## Documentation

**Start:** [Install](docs/INSTALL.md) · [User guide](docs/USER-GUIDE.md) · [Troubleshooting](docs/TROUBLESHOOTING.md) · [HTTPS](docs/HTTPS.md) · [Firewall](docs/FIREWALL.md)
**More:** [All guides](docs/README.md) · [Changelog](docs/CHANGELOG.md)

Test a spare port before you replace a live service, and open the needed ports and protocols first.
