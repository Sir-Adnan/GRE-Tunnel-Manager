# Command line

Tunnels, forwards and server settings are managed in the [web panel](WEB-PANEL.md). On the server, three entry points remain:

| Command | Purpose |
| --- | --- |
| `install.sh` | First installation: downloads and verifies a release, then runs `gtm install` |
| `gtm` | Maintains the panel or Agent: status, updates, HTTPS, port, password, logs, removal |
| `gre.sh` | The panel's privileged engine plus read-only checks; no menus since v1.6.0 |

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh | sudo bash
```

Without options a short setup asks for the address, connection security, port, login and engines; Esc cancels before anything changes. Under `curl | bash` the questions are answered on the terminal. Without a terminal, or with `--yes`, the defaults are used. Pass options after `bash -s --`:

| Option | Meaning |
| --- | --- |
| `--domain NAME` | Domain or IP for the panel; default: the detected public IP |
| `--port N` | TCP port; default: a free random port |
| `--user NAME` | Login name; default `admin` |
| `--password-env VAR` | Read the password from an environment variable (`sudo --preserve-env=VAR`) |
| `--password VALUE` | Password as an argument; visible in shell history |
| `--https` · `--self-signed` · `--http` | Let's Encrypt (default), self-signed certificate, or no encryption |
| `--email ADDRESS` | Optional Let's Encrypt contact |
| `--cloudflare-token-file FILE` | Verify a domain over Cloudflare DNS instead of port 80 |
| `--staging` | Let's Encrypt staging CA, for tests |
| `--listen IP` | Local bind address; default: all IPv4 (or `::` for an IPv6 address) |
| `--engines` | Also install iptables, nftables, HAProxy, Realm, FRP and rathole |
| `--no-update-check` | Do not check GitHub daily for a newer release |
| `--yes` | Use defaults; ask nothing |
| `--agent [--operations] [--traffic]` | Install an outbound [Agent](NODES.md) instead of the panel |
| `--remove` | Remove the panel; tunnels keep running |
| `--version X.Y.Z` · `--package-dir DIR` | Another published release, or a local archive with `SHA256SUMS` (offline) |

Without a password option a 32-character password is generated and shown once in the summary. On an existing installation the setup options are ignored (the summary says so); use the `gtm` commands below to change them.

`panel-install.sh` and `node-install.sh` still work: they translate the earlier options (`--quick`, `--protocol`, `--address`, `--letsencrypt`, `--uninstall`, `--controller` …) and call `install.sh` or `gtm`. `--quick` keeps its earlier self-signed default.

## gtm

`sudo gtm` shows the status (services, address, certificate, Nodes, updates) above a menu of the common tasks; use the arrow keys and Enter, Esc to leave. Every task is also a command:

| Command | Does |
| --- | --- |
| `gtm status [--json]` | Read-only status; JSON for scripts |
| `gtm update [--check] [--version X.Y.Z] [--yes]` | Download, verify (SHA-256) and install a newer release; restores the current one if the new one does not start |
| `gtm https` | Certificate status and choices |
| `gtm https issue [--domain NAME] [--email ADDRESS] [--cloudflare-token-file FILE]` | Trusted Let's Encrypt certificate for a domain or public IP |
| `gtm https renew [--force]` · `self-signed` · `install --cert FILE --key FILE` | Renew now, go back to self-signed, or use Certbot/acme.sh files |
| `gtm port [PORT]` | Move the panel; a failed start restores the old port |
| `gtm password [--generate \| --password-env VAR] [--user NAME]` | New login; signs out every session |
| `gtm 2fa off [--yes]` | Turn two-factor sign-in off when the phone and recovery codes are lost; signs out every session. It is turned on in the panel (Settings → Security) |
| `gtm logs [panel\|broker\|certificate\|update\|agent\|all] [-f] [-n N]` | Recent logs from the journal; `update` includes updates started from the panel |
| `gtm agent install [--operations] [--traffic]` · `agent remove` | Outbound Agent on a server without the panel |
| `gtm controller enable --url https://IP:9443` | Let Agents connect to this panel |
| `gtm remove [--yes]` | Remove the panel (type REMOVE to confirm) |

`gtm` is a link to `/usr/local/bin/gtm-panel`; `gtm-panel gtm …` is the same command. A copy of the pre-v1.6.0 `igre` shortcut is replaced by a small script that opens `gtm`. Colors follow the terminal and `NO_COLOR`; `GTM_ACCESSIBLE=1` (or `TERM=dumb`) asks questions line by line for screen readers. The interface is English: most SSH clients cannot shape right-to-left text.

Secrets are never accepted where other users could read them: passwords and Cloudflare tokens come from a hidden prompt, an environment variable or a root-only file, never from a process argument that `gtm` builds itself.

## gre.sh

```bash
sudo bash gre.sh
```

Without arguments it opens `gtm`, or installs the panel when `gtm` is missing. Earlier installer options (`--quick`, `--uninstall` …) are passed to `panel-install.sh`. On a panel server the engine is installed as `/usr/local/lib/gre-manager/manager.sh` and runs only as root through the panel's private broker.

### Read-only checks

| Command | Shows |
| --- | --- |
| `bash gre.sh --version` | Engine version |
| `sudo bash gre.sh --validate [--state-file PATH]` | Whether the saved (or given) state parses and validates |
| `sudo bash gre.sh --plan [--state-file PATH]` | The configuration the state would generate; contains addresses |
| `sudo bash gre.sh --doctor` | Host prerequisites, engines and owned services |
| `bash gre.sh --catalog` | Which method fits which job |
| `sudo bash gre.sh --haproxy-status F000001` | A HAProxy connection's backend state through its private socket |

None of these change the server or contact the network.

### Engine operations

`--api OPERATION ARGS…` is the closed, validated interface the panel's root broker calls. Input is TSV data or fixed arguments, never shell code; every mutation locks, reloads the complete state and checks revisions. Operations are grouped as follows (see `src/api.sh`):

| Area | Operations |
| --- | --- |
| Connections | `state`, `create`, `create-reviewed`, `update`, `enable`, `disable`, `delete`, `plan`, `config-render`, `connection-path`, `diagnose` |
| History and recovery | `history`, `history-restore`, `recovery-revision`, `recovery-render`, `recovery-import` |
| Links | `gre-create`, `gre-delete`, `reverse-create`, `reverse-delete`, `pair-*`, `resource-rename` |
| Addresses | `address-uses`, `address-replace`, `readdress-check`, `readdress-apply`, `extra-list`, `extra-add`, `extra-delete` |
| DNS | `dns-resolve`, `dns-cache`, `dns-policy`, `dns-refresh`, `dns-status`, `dns-apply`, `dns-restore` |
| Firewall | `firewall-status`, `firewall-apply`, `firewall-confirm`, `firewall-revert` |
| Maintenance | `kernel-refresh`, `flows-reset`, `forward-exclude`, `doctor`, `portfw-rules` |
| Optimization | `optimize-status`, `optimize-plan`, `optimize-apply`, `optimize-undo`, `optimize-remove` |
| Engines | `install`, `component-policy`, `component-update` |
| Old installations | `legacy-scan`, `legacy-retire` |

There are no prompts: the caller has already reviewed the change (the panel shows a preview first), so the request itself is the confirmation. Prefer the panel; run an operation by hand only for recovery or on a server without the panel, for example the command the **IP addresses** page shows for a peer after an IP change:

```bash
sudo bash gre.sh --api address-replace 203.0.113.5 203.0.113.10 remote all
```
