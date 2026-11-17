# GRE Tunnel Manager v1.7.0

See how fast every connection is moving right now, a redesigned Traffic page, and a panel that fits small phones better.

## Install

```bash
sudo bash -c "$(curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/install.sh)"
```

Every recipe and option: [Install, update and remove](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/INSTALL.md) ([فارسی](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/fa/INSTALL.md)).

## New

- **Live speed per connection.** With usage collection on, every connection card and table row shows its current download and upload speed, refreshed every 2 seconds while the page is open. The speeds come from the kernel counters collection already keeps; nothing runs in the background and no traffic passes through the panel.
- **Traffic page redesign:** live throughput with a one-minute chart, the busiest connections right now, this cycle's totals and top user, quota alerts, and each row's live speed and share of usage. With collection off, one card explains it and turns it on. GRE tunnels are listed but not added to totals, so forwarded bytes are never counted twice.

## Improved

- **Addresses stay whole.** A route never splits an IP address or port; narrow cards stack the route on two lines.
- **Copy, don't select.** A long press selects text again (bulk selection is the **Select** button). Tap a destination to copy it.
- **No keyboard on open.** Opening a connection or tunnel on a phone no longer focuses a field.
- **Small phones:** spacing, icons, the header and the bottom bar scale down on narrow or zoomed screens, while text and touch targets stay readable.
- **IP addresses:** roomier rows, copy buttons, and **Main IP** only on the real main address.
- **DNS:** latency and the **Fastest**/**In use** tags no longer overlap.

## Upgrade

`sudo gtm update`, or **Settings → Updates**. Settings, certificates, connections, traffic history and Nodes are kept. Verify `SHA256SUMS`.

Local checks cover the Python and Go suites (race detector included), frontend build/lint/tests, ShellCheck, and the panel at 320 to 412 px and desktop widths in both languages. Live counters on a busy public server remain a deployment check.
