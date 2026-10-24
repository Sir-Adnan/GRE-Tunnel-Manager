# Web panel

Manage local tunnels from a Persian/English interface on desktop or mobile. The panel runs separately from the traffic path; stopping it does not stop independently managed tunnels. Other servers can join as optional [Nodes and Agents](NODES.md).

Version **v1.3.3** adds **Backup & restore** for password-protected recovery downloads and migration to a fresh server, with optional traffic records and explicit address/interface replacement. Imported resources stay paused. See [Backup and restore](BACKUP-RESTORE.md) for scope, external certificates, Node identities and recovery steps.

## Installation and login

On Debian/Ubuntu with systemd:

```bash
curl -fsSL --ipv4 https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/panel-install.sh -o panel-install.sh && sudo bash panel-install.sh --quick
```

The terminal **Web Panel** menu uses the same installer. It downloads a versioned archive, verifies its checksum and installs the Go executable, embedded frontend and matching Bash helper. Managed servers need no Node.js, Python, compiler, Docker or database server.

### Quick and custom setup

Quick setup uses HTTPS, detects the public IP, selects a free random port and generates administrator credentials. The URL and generated password are printed once; save them. Running the installer without `--quick` offers numbered quick/custom and HTTPS/HTTP choices. Custom setup asks for the address, port, username and a hidden, confirmed password.

| Option | Fresh-install behavior |
| --- | --- |
| `--quick` | Automatic setup without questions |
| `--protocol https` / `--protocol http` | Browser protocol; HTTPS by default |
| `--address IP_OR_DOMAIN` | Reachable IP or ASCII domain without scheme, port or path; skips IP discovery |
| `--port PORT` | Selected TCP port; omitted or `0` selects an available random port |
| `--username USER` | Default `admin`; 3–40 ASCII letters, digits, dots, dashes or underscores |
| `--listen LOCAL_IP` | Local bind; all IPv4 addresses by default, or `::` for an IPv6 address |
| `--install-engines` | Preinstall supported engines without creating tunnels; none by default |
| `--package-dir DIR` | Use a matching local archive and `SHA256SUMS` |

After downloading the installer, for example:

```bash
sudo bash panel-install.sh --quick --protocol http --address 203.0.113.10 --port 8080
sudo bash panel-install.sh --quick --address panel.example.com --port 8443
```

Chosen passwords require at least eight Unicode characters and at most 72 UTF-8 bytes. Quick setup generates a 32-character random password. Password arguments, URLs and environment variables are not accepted; only the bcrypt hash is stored. Avoid saving the one-time credential output in shared logs.

### Address discovery, certificates and access

Allow the selected TCP port in the server/provider firewall. Setup checks current sockets but does not model all custom DNAT rules or automatically open firewalls. A random port is not an authentication mechanism.

When no address is supplied, bounded HTTPS requests to `api.ipify.org` and `api6.ipify.org` discover the outgoing public IP. Behind NAT or on multi-address servers, pass the actual reachable entrance with `--address`. Failed quick discovery stops before configuration is written. A domain must already resolve to the server; setup does not register it or edit DNS. IPv6 URLs use brackets; domain listeners default to IPv4 unless `--listen ::` is supplied.

HTTPS initially uses a self-signed certificate. Verify its SHA-256 fingerprint over SSH before trusting it. For an operator-managed certificate, set absolute `certificate` and `private_key` paths in the restricted configuration and restart. Automatic ACME and trusted reverse-proxy/forwarded-header support are not implemented; access and Origin checks refer to the direct listener.

Explicit HTTP works on an IP without a certificate, but browser login and management traffic are unencrypted. Authentication, Origin and CSRF checks remain required. Browser HTTP does not weaken the separate TLS Agent channel.

### Existing installations and recovery

Run the current installer again to upgrade to the matching **v1.3.3** package, then refresh the browser. Downloading the script alone does not replace an installed binary. The installer preserves existing address, protocol, credentials and certificates; setup flags do not reconfigure an existing installation.

Checksums, binary version and existing configuration are checked before a working service stops. Installation is locked against concurrent runs. Failures after replacement are not a host-wide atomic transaction: inspect logs and restore the previous matched package when needed. Keep private backups of configuration and Node identities.

```bash
sudo gtm-panel address
sudo gtm-panel reset-password
sudo systemctl restart gre-manager-panel
sudo systemctl status gre-manager-panel --no-pager
sudo journalctl -u gre-manager-panel -n 100 --no-pager
```

The address command never prints a password. Restart after password reset to revoke existing sessions. Back up the config before changing its listen/protocol/public_host fields; switching from HTTP to HTTPS also requires certificate/key files. Existing TLS files are retained when selecting HTTP.

An interrupted first setup can leave TLS files; inspect and move only those owned files to a private backup before retrying. Older binaries may reject newer configuration/state schemas, so downgrade needs matching prior backups. See [Operations](OPERATIONS.md) and [panel removal](PANEL-REMOVAL.md).

## Connections and configuration

| Area | Managed features |
| --- | --- |
| iptables/nftables | IPv4/IPv6 TCP/UDP forwarding, source policy, weighted destinations and owned rules |
| HAProxy | TCP, checks, balancing/failover, bounded IP affinity and TLS/SNI/HTTP routing |
| Realm | TCP/UDP, weighted targets, timeouts/keepalive, PROXY metadata and gated transport options |
| GRE | Keyed GRE/ip6gre setup, MTU, names, service actions and dependency-aware removal |
| FRP/rathole | Entrance/destination setup, supported transports and service actions |

The [capability matrix](ENGINE-CAPABILITIES.md) defines supported versions and limits. Adapters do not expose every native engine option. General editors act on the panel host; remote writes are limited to [coordinated GRE/FRP creation](PAIRED-CONNECTIONS.md).

Connection forms start with entrance ports and destinations, side by side on desktop and stacked on mobile. Names are optional; advanced engine settings have a separate tab. The footer summarizes the route and whether it will start after saving. Review precedes every apply. Changed connection, GRE/reverse and configuration drafts ask before closing; drafts are not stored in the browser. **Relative share** controls weighted distribution, not priority or a bandwidth guarantee. [Setup presets](CONNECTION-PROFILES.md) initialize settings without changing existing records automatically.

Select a connection name to inspect its summary and copy destination endpoints. Edit stays directly accessible; the **More actions** menu contains configuration, supported logs, start/stop and deletion. The toolbar's **Preview all configurations** renders enabled local connections without applying anything. The [configuration editor](CONFIGURATION-EDITOR.md) supports managed JSON and a restricted native-text subset, with revision checks, validation and review. GRE/reverse file views are read-only; reverse secrets are masked. Arbitrary paths, commands and unrestricted overrides are not exposed.

Page addresses such as `#/haproxy` can be bookmarked. Search/status filters, selected connection details and traffic tabs are retained in the URL. Browser back/forward works between pages. The header's server button shows the local host, protocol and separately copyable IPv4/IPv6 addresses. These remain local operations; remote management is limited to the capabilities described below.

## Traffic usage

Collection and retained history are off by default. Tabs separate **All connections**, **Details & history** and **Traffic collection**. The list has search, method filters, 20-row pages and per-row actions for labels/quotas, reset, supported manual stop or forgetting deleted-resource accounting. Missing samples display as unavailable.

Collection adds only owned `inet gtm_panel_metrics` counters and periodic sampling, including for iptables/relay ports. GRE uses interface counters. Disabling removes the accounting table and pauses sampling while retaining totals. Disable collection before stopping the panel if you want those kernel counters removed.

Bytes are network-layer usage, not provider billing. GRE and forwarding counters may overlap and are never summed. Quotas are advisory and do not stop traffic automatically. History is bounded; remote summaries are read-only. See [Traffic accounting](TRAFFIC-ACCOUNTING.md) for coverage, lost-sample limits, reset semantics and CSV export.

## Multiple servers

The panel host is already a local Node and needs no Agent. Nodes has separate server inventory and **Connect two servers** tabs. **Add server** opens setup guidance when the Controller is disabled. Enable its dedicated TLS listener, allow its port and refresh, then create an invitation for the other server's outbound Agent. Browser HTTP and Agent TLS are independent. See [Nodes](NODES.md), [paired connections](PAIRED-CONNECTIONS.md) and [remote traffic](REMOTE-TRAFFIC.md).

## Security and runtime

The public service runs as restricted `grepanel`; privileged typed operations use a protected local Unix broker and Bash API. Forwarding changes reload complete locked state, compare revisions, validate, snapshot and recover on failure. No public shell or arbitrary-file API exists.

Sessions are memory-only, expire after four hours and use HttpOnly/SameSite cookies plus Secure on HTTPS. Writes require exact Origin and CSRF checks. Requests, login attempts and jobs are bounded. Restarting the public process clears sessions/jobs; a broker operation can still finish, so refresh actual state after reconnecting.

Production runs two Go processes plus the selected tunnel engines. Node/Vite/TypeScript are build tools. A memory-limit setting is not a fixed RSS guarantee; no throughput, CPU or RAM benchmark is claimed. For implementation details, see [Architecture](ARCHITECTURE.md), [Server artifacts](ARTIFACTS.md) and [Interface conventions](INTERFACE.md).
