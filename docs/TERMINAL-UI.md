# Terminal interface and setup flows

See the [README](../README.md) for installation. The terminal interface stays in English; web-panel language and appearance settings do not affect it.

## Launching the interface

The manager opens in the current SSH terminal. Each engine has its own header and menu. Enter a number and press Enter; use `0` to go back.

```bash
curl -fsSL https://raw.githubusercontent.com/Sir-Adnan/GRE-Tunnel-Manager/main/gre.sh -o gre.sh
bash gre.sh --version
sudo bash gre.sh
```

Omit `sudo` when already root. Downloading replaces the local script but does not itself change tunnels. Update an installed shortcut through **Tools → Install / Update igre**, then reopen it.

## HAProxy setup

1. Open **HAProxy Tunnel → Add Tunnel**.
2. Enter a local port, comma-separated list or short range.
3. Enter the destination IP and destination port separately; combined `IP:port` is also accepted.
4. Review the mapping and choose **Save & apply**.

Names are generated automatically. This adapter is TCP-only. Change the name or listen address through **Optional settings** in the review step. For several ports, choose numerically whether destinations use the entered port or preserve each local port number.

## Realm and kernel forwarding

The port/destination flow is the same. Select the protocol numerically: TCP, UDP or both. Optional settings can stay closed for ordinary setups. HAProxy/Realm default to all local IPv4 addresses; kernel forwarding proposes a specific local address from routing information. Behind cloud NAT this may be private. Review shows the actual address before application.

## Dedicated managers

| Task | Menu action |
| --- | --- |
| Create a connection | Add Tunnel / Add forward |
| Add destinations | Load Balancing |
| Inspect, edit or delete | Corresponding action in the engine menu |
| Enable/disable without deleting configuration | Start / Stop |
| Service status, logs or restart | Status & Logs |
| HAProxy options | Advanced Settings |

Each engine lists only its own resources. Group deletion accepts space-separated row numbers such as `1 3 4`. Disabling retains configuration; deleting removes the selected managed entry.

## Server information in the header

The terminal header/banner shows the application, version and current section. The large title is an **ASCII art banner**, shown only when at least 68 columns and 34 rows are available. Smaller windows use a compact title.

Host information includes hostname, OS on wide screens, observed public egress IP and locally assigned addresses. Addresses are not silently truncated. Narrow windows wrap their labels or the full address. Interactive setup redisplays the header. Copy an address using the SSH client's normal text selection; the terminal manager does not control the clipboard.

**Public v4/v6** means the egress address observed externally; **Local v4/v6** means an address assigned to the server. NAT can make them different. A public address is not necessarily valid for local binding. Header discovery does not change setup defaults. Showing IPv6 does not prove inbound reachability.

**Provider** shows the network owner, ASN and approximate country; it does not guarantee the exact datacenter or reseller. One optional HTTPS request to the [IP information service](https://ipwhois.io/documentation) obtains this information, with a two-second total timeout and local fallback. Only the address family actually observed by that service is labeled public; both families are not probed separately.

Successful and failed results are cached only in memory for the current script run. Opening submenus does not repeat the request. Use **Tools → Refresh Server Info** to retry. There is no cache file, timer or background service. Preview/demo use sample information; noninteractive commands do not perform this online header lookup.

Disable online lookup:

```bash
sudo env GTM_SERVER_LOOKUP=0 bash gre.sh
```

## Fixed terminal colors

The interface uses a fixed cyan, purple and green palette without repainting the terminal background. Terminal themes, light/dark settings, layout choices and Persian/Finglish modes have been removed. Older appearance files are not read or executed; existing files are not silently deleted.

For plain output:

```bash
sudo env NO_COLOR=1 bash gre.sh
```

Redirected output, pipes and `TERM=dumb` also omit colors. Fonts and the terminal background belong to the SSH application.

## Safe interface previews

```bash
bash gre.sh --preview home
bash gre.sh --preview haproxy
bash gre.sh --preview realm
bash gre.sh --demo
```

Previews do not require root. The Bash interface is the actual terminal UI; the earlier HTML terminal mockup was a design artifact. The optional Go web panel is a separate installation.
