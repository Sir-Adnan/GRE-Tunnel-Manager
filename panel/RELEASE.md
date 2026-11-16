# GRE Tunnel Manager v1.6.1

An installer that shows what it is doing, a fix for setups that stalled before the first screen, temporary-IP detection and a better panel on phones.

## Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"
```

Without questions, for example HTTP with your own port and login:

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)" @ --http --port 8080 --user admin --password 'my-long-password' --yes
```

Every recipe and option: [Install, update and remove](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/INSTALL.md) ([فارسی](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/fa/INSTALL.md)).

## Fixed

- **Setup could hang with nothing on screen** after "Package verified" under `curl … | sudo bash`. sudo (`use_pty`, the Ubuntu and Debian default) gives the script a terminal that receives no keystrokes. v1.6.0 queried that terminal's colors first and waited forever. Now the terminal is never queried, and the setup runs on the terminal sudo was started from, so questions can be answered again. `GTM_THEME=light` selects the light palette.
- **Realm, FRP and rathole installation failed on Ubuntu and Debian:** the download's version check ran from `/run`, which these systems mount noexec. Downloads now stage under `/usr/local/lib/gre-manager`. rathole's `unzip` is installed when missing.
- Package installs can no longer wait on a hidden debconf or needrestart question.

## Improved

- **Progress you can see:** download progress bar, then one live line per step with a spinner, elapsed time, a step counter and the latest command output. Finished steps keep their duration. Output is shown in full only for a step that fails.
- **Faster `--engines`:** one package-list refresh and one `apt-get` run for iptables, nftables, HAProxy and socat.
- **Temporary IPs:** the IP addresses page marks an address added with `ip address add`, which a restart removes. **Keep after restart** makes it permanent.
- **Phones:** routes no longer break across lines, and lists are not nested in a card. The top bar and page actions fit small screens. Editor rows show the whole address. Tested from 320 to 412 px wide.
- **Docs:** one installation guide, a troubleshooting guide, a shorter README, and Persian guides for installation, use, troubleshooting, HTTPS and the firewall.

## Upgrade

`sudo gtm update`, or **Settings → Updates**. Settings, certificates, connections and Nodes are kept. Verify `SHA256SUMS`.

Local checks cover the Python and Go suites, frontend build/lint/tests, ShellCheck, installation in a disposable systemd container, and the panel at phone widths in both languages. A Let's Encrypt order, provider firewalls and reboots on a public server remain deployment checks.
