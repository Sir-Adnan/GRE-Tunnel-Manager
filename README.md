<div align="center">

# GRE Tunnel Manager

### Server tunnels and port forwarding, made simple.

GRE · iptables · nftables · HAProxy · Realm · FRP · rathole

[![Release](https://img.shields.io/badge/release-v1.2.2-0891b2?style=flat-square)](docs/CHANGELOG.md)
[![Checks](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml/badge.svg)](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/actions/workflows/checks.yml)
![Bash](https://img.shields.io/badge/runtime-Bash-334155?style=flat-square)

**English** · [فارسی](README.fa.md)

[Quick start](#quick-start) · [User guide](docs/USER-GUIDE.md) · [HAProxy](docs/HAPROXY.md) · [Changelog](docs/CHANGELOG.md)

</div>

---

## Quick start

**You need:** a Debian/Ubuntu server with systemd, SSH access, `curl`, and root or sudo access.

Paste this **single command** into your server's terminal:

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh -o gre.sh && sudo bash gre.sh
```

Already logged in as **root**? Leave out `sudo`. The script is saved as `gre.sh` in your current folder. To run it again, use `sudo bash gre.sh` from that folder. Downloading again replaces that local copy.

Missing curl? Install it with `sudo apt-get update && sudo apt-get install -y curl` first. Optional tunnel engines are installed only when you choose to apply a setup that needs them.

## Choose what you need

| Menu | Use it for |
| --- | --- |
| **1 · GRE Tunnel** | Create, show or delete GRE and Simple GRE tunnels |
| **2 · Port Forwarding** | Forward TCP/UDP ports with iptables or nftables |
| **3 · HAProxy Tunnel** | Manage HAProxy TCP tunnels, balancing, services and logs |
| **4 · Realm Tunnel** | Manage Realm TCP/UDP tunnels and services |
| **5 · Reverse Tunnel** | Set up FRP or rathole on both servers |
| **6 · Load Balancing** | Send traffic to more than one server |
| **7 · Tools** | Server status, backups, cleanup and help |

Each engine has its own menu. Add, show, edit and delete are together; type an option number and press Enter. GRE is optional for direct forwarding.

## Your first HAProxy tunnel

1. Open **HAProxy Tunnel → Add Tunnel** and enter the **local port**, such as `443`.
2. Enter the **remote IP**, then the **remote port**. A combined `IP:port` also works.
3. Review the mapping and choose **Save & apply**.

The tunnel gets a name automatically. Renaming and a specific listen IP are optional. HAProxy and Realm listen on all local IPv4 addresses by default; kernel forwarding selects a local address from the server's routing information. Review shows the chosen address before applying.

Need several ports? Enter `443,8443` or a short range such as `8000-8003`. Choose whether they all use the entered remote port or keep their original port numbers. Every mapping is shown before saving, with a separate managed entry per local port; up to 32 ports per setup. Existing entries are edited individually.

## What is included?

- **GRE / ip6gre** with the existing peer configuration and MTU controls.
- **Kernel forwarding** for TCP/UDP, without a resident manager process.
- **HAProxy TCP** with health checks, failover, timeouts and restricted local status.
- **Realm TCP/UDP**, plus **FRP** TCP/WS/WSS/QUIC and **rathole** Noise reverse tunnels.
- **Managed changes:** validation, grouped deletion and automatic forwarding restore points.
- **A fixed English terminal UI:** dedicated headers, numbered choices and short setup steps. No theme or language setup is required.

## Before using your main service

Allow the required ports and protocols in your server/provider firewall. GRE needs protocol 47 and does not encrypt traffic. Use UDP forwarding for WireGuard/AmneziaWG; this HAProxy adapter is TCP-only. Test a separate port before moving a live service.

## Documentation

[Terminal & setup guide](docs/TERMINAL-UI.md) · [Detailed user guide](docs/USER-GUIDE.md) · [Operations & recovery](docs/OPERATIONS.md) · [HAProxy settings](docs/HAPROXY.md) · [Legacy cleanup](docs/TUNING-CLEANUP.md)

For contributors: [Architecture & docs](docs/README.md) · [Development](docs/DEVELOPMENT.md) · [AGENTS.md](AGENTS.md)

The historical v13.9 code and its documentation are kept in [legacy](legacy/README.md).
