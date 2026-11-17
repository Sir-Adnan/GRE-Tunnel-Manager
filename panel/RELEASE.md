# GRE Tunnel Manager v1.7.1

A live dashboard, the panel password changed from the panel, and layout fixes across the panel.

## Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"
```

Every recipe and option: [Install, update and remove](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/INSTALL.md) ([فارسی](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/fa/INSTALL.md)).

## New

- **A live dashboard.** Four figures (live traffic, connections, 24-hour health, needs attention), your connections with their live speed, the server's load, and a **Tunnel health** card with each tunnel's last 24 hours. Every address of the server can be copied from the header.
- **Change the password in the panel.** **Settings → Security → Sign-in → Change password**: current password, new password and, with two-factor sign-in on, a code. No restart; other browsers are signed out. `sudo gtm password` stays the recovery path.
- **Health filter.** All, Problems or Healthy, with counts and search; problems are always listed first.

## Fixed

- Dashboard routes stack like the connection cards instead of crowding one line, and a destination list no longer opens a help tooltip on top of itself.
- **Compact** density now changes the spacing (it had no effect).
- **Nettinx** draws charts, live rates and status colors (they were blank).
- Health rows line up, the change history is aligned, and the restore and import file pickers match their forms.
- Live speed in the connections table no longer runs under the on/off switch on wide screens.
- Every command the panel offers to copy uses the current installer form, `sudo bash -c "$(curl …)" @ …`.

## Upgrade

`sudo gtm update`, or **Settings → Updates**. Settings, certificates, connections, traffic history and Nodes are kept. Verify `SHA256SUMS`.

Local checks cover the Python and Go suites (race detector included), frontend build/lint/tests, ShellCheck, and the panel at 320 px to wide desktop in both languages. A real phone and a busy public server remain deployment checks.
