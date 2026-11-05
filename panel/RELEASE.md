# GRE Tunnel Manager v1.4.0

Health failover for balanced kernel forwards, a new reversible server optimization module and a leaner terminal. Everything new is off until you turn it on or apply it.

## Health

- **Failover** for nftables and iptables forwards with several destinations, chosen per forward. Their destinations are probed every 5 seconds (2–30 s). A destination that is down stops receiving new connections, its tracked flows are cleared so clients reconnect to a live one, and it returns when it answers again. At least one destination always stays; the saved configuration is not changed and a reboot, an edit or turning monitoring off restores every destination.
- HAProxy destinations show HAProxy's own check results (status, check time, sessions, backup) instead of a second probe.
- Expanded rows show the 24-hour share of failed checks, new connections per destination for balanced nftables forwards and an on-demand **path MTU test** for GRE links with a suggested MTU.

## Optimization

A new **Optimization** page (terminal: **Tools → Server optimization**) with four opt-in groups for tunnel and forwarding servers: Connection tracking, Packet queues, Relay TCP and Tunnels & routing. Values were chosen from scratch; the old tuning profiles are gone.

- No recommendation is ever worse than the server's live value, including the provider's defaults: limits only grow, timeouts only shrink, buffer triples grow per field and equivalent choices (`cake`, `bbr2`) stay. Such keys are shown as kept.
- Every change is reviewed first and journaled. **Undo** goes back step by step (20 steps), **Restore originals** undoes one group and **Reset everything** returns every value and deletes the panel's files.
- ServerTools and other drop-ins that set the same keys are detected and shown, never edited. The panel's drop-in sorts last and wins at boot. Tuning applied with v1.3.7 or earlier is imported on the first change and stays resettable.

See [Server optimization](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/OPTIMIZATION.md) for every value and why.

## Terminal

- The v13.x scripts (`gre-stable.sh`, `legacy/`) and the old numbered menu are removed. Creating and deleting GRE in the terminal uses the same engine as the panel.
- **Tools → Retire old installation** still removes v13.x forwards, Simple GRE and old tuning files. GRE tunnels created by old versions keep working.

## Upgrade and verification

Run the current panel installer to install the matching v1.4.0 package, then refresh the browser. Existing credentials, certificates and managed tunnel settings are kept. Use matching Controller/Agent packages when upgrading Nodes. Failover's flow clearing needs the `conntrack` package.

Linux amd64/arm64 archives contain the executable, embedded frontend, matching Bash helper and dependency notices. Verify `SHA256SUMS`. Managed servers do not need Node.js, Python or a compiler.

Tested with unit tests and in isolated Linux network namespaces, including failover keeping new connections off a dead destination. Failover, flow counts, the MTU test and boot-time optimization have not yet been verified on a real server.
