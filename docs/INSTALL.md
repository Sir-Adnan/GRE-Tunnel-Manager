# Install, update and remove

**English** · [فارسی](fa/INSTALL.md)

Everything about getting the panel onto a server, in one place. Feature guides start at the [documentation index](README.md).

## Requirements

- Debian or Ubuntu with systemd, on x86_64 or arm64, as root (or with `sudo`).
- A 6 MB download and a few tens of MB on disk. Nothing is compiled: the installer downloads a prebuilt release and checks its SHA-256 sum. No Node.js, Python, Docker or database is installed.
- A free TCP port for the panel. For a trusted certificate, TCP port 80 must reach the server for a few seconds (or use Cloudflare DNS for a domain).

## Install in one line

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"
```

The installer shows each step as it runs: download with a progress bar, checksum, then a short setup that asks for:

1. **Address:** the server's public IP (detected) or a domain that points to it.
2. **Security:** HTTPS with Let's Encrypt (trusted, renews itself), HTTPS self-signed, or plain HTTP.
3. **Port:** empty picks a free random port.
4. **Login name and password:** a strong password can be generated and is shown once at the end.
5. **Engines:** install iptables, nftables, HAProxy, Realm, FRP and rathole now, or later from the panel.

The panel starts and the summary prints its address and login. Then open the panel's TCP port in the server and provider firewall, and sign in. Esc cancels the setup before anything changes.

`curl -fsSL …/install.sh | sudo bash` works too; the installer then asks its questions on the terminal sudo was started from.

## Install without questions

Add options after `@` (it stands in for the script name). Every option answers its question; `--yes` uses defaults for the rest.

| I want | Command |
| --- | --- |
| Defaults: trusted HTTPS for the public IP, random port, generated password | `sudo bash -c "$(curl -fsSL URL)" @ --yes` |
| **HTTP**, my own port and login | `sudo bash -c "$(curl -fsSL URL)" @ --http --port 8080 --user admin --password 'my-long-password' --yes` |
| HTTPS for my domain | `sudo bash -c "$(curl -fsSL URL)" @ --domain panel.example.com --port 2053 --yes` |
| HTTPS for a domain over Cloudflare DNS (no port 80) | `sudo bash -c "$(curl -fsSL URL)" @ --domain panel.example.com --cloudflare-token-file /root/cf.token --yes` |
| Self-signed HTTPS | `sudo bash -c "$(curl -fsSL URL)" @ --self-signed --port 2053 --yes` |
| Everything, plus all tunnel engines | add `--engines` |

`URL` is `https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh`.

A password on the command line stays in the shell history. To avoid that, put it in a variable:

```bash
read -rs PANEL_PASS && export PANEL_PASS
sudo --preserve-env=PANEL_PASS bash -c "$(curl -fsSL URL)" @ --http --port 8080 --password-env PANEL_PASS --yes
```

Passwords need 8 characters or more (up to 72 bytes). Only a bcrypt hash is stored.

### All options

| Option | Meaning |
| --- | --- |
| `--domain NAME` | Domain or IP for the panel; default: the detected public IP |
| `--port N` | TCP port; default: a free random port |
| `--user NAME` | Login name; default `admin` |
| `--password VALUE` · `--password-env VAR` | Login password, or the variable that holds it; default: generated |
| `--https` · `--self-signed` · `--http` | Let's Encrypt (default), self-signed certificate, or no encryption |
| `--email ADDRESS` | Optional Let's Encrypt contact |
| `--cloudflare-token-file FILE` | Verify a domain over Cloudflare DNS instead of port 80 |
| `--staging` | Let's Encrypt staging CA, for tests |
| `--listen IP` | Local bind address; default: all IPv4 (or `::` for an IPv6 address) |
| `--engines` | Also install every tunnel engine |
| `--no-update-check` | Do not check GitHub daily for a new release |
| `--yes` | Ask nothing; use defaults |
| `--agent [--operations] [--traffic]` | Install an outbound [Agent](NODES.md) instead of the panel |
| `--remove` | Remove the panel; tunnels keep running |
| `--version X.Y.Z` · `--package-dir DIR` | Another release, or a local archive with `SHA256SUMS` (offline) |

On a server that already has the panel, setup options are ignored and its address, port, login and certificates are kept; change them with `gtm` (below).

## After installation: `gtm`

```bash
sudo gtm                 # status (services, address, certificate, updates) and a menu
sudo gtm password        # new login password
sudo gtm port 2053       # move the panel; a failed start restores the old port
sudo gtm https issue     # get (or retry) a trusted certificate
sudo gtm logs -f         # follow the panel log
sudo gtm 2fa off         # lost the authenticator? turn two-factor sign-in off
```

Every command is listed in [Command line](COMMAND-LINE.md).

## Update

In the panel: **Settings → Updates → Update**. On the server:

```bash
sudo gtm update
```

The new release is verified before anything stops. If it does not start, the previous one is restored. Tunnels keep running during an update. Running the installer again also repairs an installation and keeps its settings.

## Remove

```bash
sudo gtm remove
```

It shows what is removed and kept and asks you to type `REMOVE`. Only the panel goes: tunnels, forwards and engine binaries keep working. Details and refusals: [Panel removal](PANEL-REMOVAL.md).

## Coming from an older version

- **v1.5.x and later:** run `sudo gtm update` (v1.6.0+) or the one-line installer. Logins, certificates, connections and Nodes are kept.
- **v13.x scripts:** install the panel, then retire the old forwarding script, Simple GRE and tuning files as described in [Retiring old installations](RETIRING-OLD-INSTALLS.md). Old `gre-tun-N` tunnels keep working and appear in the panel.
- `panel-install.sh` and `node-install.sh` still accept their earlier options and call the new installer.

## If something goes wrong

See [Troubleshooting](TROUBLESHOOTING.md): the panel does not open, the certificate fails, the installer seems stuck, a lost password, or an IP that disappears after a restart.
