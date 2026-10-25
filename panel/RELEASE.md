# GRE Tunnel Manager v1.3.4

Clearer connection workflows, optional quota enforcement and lightweight live server readings. This release also adds reviewed configuration imports and explicit engine maintenance.

## Traffic and dashboard

- Show numeric cycle quotas, usage progress and applied pause state on desktop and mobile. Keep labels, resets, history and CSV export together.
- Optionally pause local forwarding, supported public reverse listeners or a GRE interface when its selected cycle limit is reached. Owned nftables rules block both directions, including established flows; reset the cycle, raise the limit or turn off the policy to resume. Services remain configured and running.
- Quota detection is sampled, not byte-exact. The default interval is 60 seconds, so usage can exceed the quota between checks. Collection and the broker must run to detect new crossings. Remote quota edits and reboot-independent enforcement are not included. Existing policies remain advisory until explicitly enabled; portable restore disables automatic pauses.
- Add CPU, memory and default-route receive/send rates with visible-dashboard polling, pause/resume and 5/15-second cadence. Use cached Linux counters without an extra daemon, database or disk history.

## Configuration and engine maintenance

- Import supported HAProxy TCP configurations, simple Realm TOML or managed JSON through a bounded, additive review. Reject unsupported/lossy syntax and stale reviews, preserve unrelated records and save paused unless activation is selected.
- Improve direct native editing for supported HAProxy/Realm configurations. Allow strict single-destination iptables/nftables edits only when the complete managed rule set can round-trip; submitted firewall text is never executed.
- New HAProxy connections use automatic native connection sizing, no per-target cap, logs off and active checks off. Blank optional caps work. Preserve saved and legacy semantics; presets deliberately enable checks and reset stale options. Finite connection/inactivity timeouts remain.
- Add manual official version checks and confirmed updates using reviewed package candidates or verified binary pins, with retained binaries and recovery. Latest-upstream discovery does not imply compatibility with every release.
- Add local FRP KCP transport and recognize Realm's official version/build-feature output. Existing Node protocol and paired-connection capabilities stay unchanged.

## Interface

- Repair mobile identity wrapping and destination inspection; keep edit, start/stop and configuration actions directly available.
- Balance desktop connection columns, compact filters and appearance controls, and add footer shortcuts. Preserve Nettinx colors, Persian RTL/English LTR, Latin digits and reduced-motion support.

## Upgrade and verification

Run the current panel installer to install the matching v1.3.4 package, then refresh the browser to load its embedded interface. Downloading the script alone does not upgrade the executable. Existing credentials, certificates and managed tunnel settings are retained. Use matching Controller/Agent packages when upgrading Nodes.

Linux amd64/arm64 archives contain the executable, embedded frontend, matching Bash helper and dependency notices. Verify `SHA256SUMS`. Managed servers do not need Node.js, Python or a compiler.

Validation covers Python/Bash, ShellCheck, frontend build/lint/tests, Go race/vet, real isolated networking and responsive browser flows. A private Linux test verifies quota blocking of an established TCP flow, unrelated-listener isolation and reset/resume. Demo screenshots and simulated counters are not performance measurements. Public VPS rollout, reboot behavior, native arm64 execution and sustained capacity remain deployment checks.

See [Traffic accounting](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/TRAFFIC-ACCOUNTING.md), [Configuration editor](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/CONFIGURATION-EDITOR.md), [Engine maintenance](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/ENGINE-MAINTENANCE.md) and [Kernel/userspace responsibilities](https://github.com/Sir-Adnan/GRE-Tunnel-Manager/blob/main/docs/KERNEL-AND-USERSPACE.md).
