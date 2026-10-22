# Development

Edit `src/*.sh`, run `python3 tools/build.py`; do not hand-edit generated `gre.sh`. The build is deterministic and uses Python stdlib. Runtime is Bash, without Python/jq dependencies.

## Contracts

- Keep `gre-stable.sh` unchanged; preserve legacy numbers and GRE wire defaults.
- `legacy/` is the supplied historical archive. Keep its script bytes unchanged; its original whitespace is excluded from diff whitespace checks through .gitattributes. Maintain legacy/README.md as an archive guide, not as current-release documentation.
- No resident manager. Optional relay services are explicit user choices.
- Use data records, arrays, printf, read -r, bounded numeric conversion and explicit error handling. Never source user config or eval rule strings.
- Operate only on owned chains/table/services, not host firewall state.
- Cross-module results: R_* validated record, EP_* endpoint, P_* FRP config.
- Keep LF endings. Source modules are bundled, not downloaded at runtime.
- The terminal UI is English-only with one fixed foreground palette, dedicated engine headers and numbered choices. No themes, translations, background fills or preference files. Respect NO_COLOR/non-TTY/dumb output.
- Forms collect data without installing or changing resources. Local ports come first; remote IP and port are separate with IP:port convenience input. Names are automatic; optional details are on review. Batch at most 32 listeners into existing records and reconcile the full state once under lock. Never lose other engines through presentation filters.

## Checks

```bash
python3 tools/build.py --check
python3 -m unittest discover -s tests -v
shellcheck -s bash -S warning -e SC2034 src/{core,server_info,ui,haproxy,state,firewall,relays,transports,rathole,catalog,inspect,forms,tuning,cleanup,menus}.sh
bash gre.sh --preview haproxy
sudo bash tests/linux_namespace.sh
```

SC2034 is excluded in per-module lint because shared public variables appear unused in isolation. Existing legacy lint debt is outside this new-module gate.

Linux namespace tests need network namespace capabilities, ip, nft, nsenter and Python 3. Optional installed engines are exercised; tests never install/download them. WSS testing needs openssl and HAProxy. CI installs nftables, iptables, HAProxy, socat and ShellCheck.

Tests create a private parent network namespace and two child namespaces with veth pairs and an echo backend. They check IPv4/IPv6 nft syntax, repeat apply, deletion, actual TCP/UDP NAT request/reply, preflight rejection preserving live rules/traffic, a real keyed GRE path (MTU 1430, 128 KiB TCP and 1200-byte UDP), and available relay engines. GRE kernel support is required. Host networking is untouched; temporary processes are stopped on exit.

GRE tests capture real outgoing SYN options with an AF_PACKET socket, checking the 1390 route MSS and preservation of a peer's smaller 1200 MSS. An installed rathole 0.5.0 enables Noise TCP/UDP packet tests plus wrong-server-key rejection. Tests do not download it; CI can skip optional absent engines. Before changing a component pin, inspect tagged upstream config/CLI contracts and verify the actual release archive. Do not use a short `--version` assumption: official rathole 0.5.0 prints a multiline build report.

HAProxy tests query real restricted sockets, reload a master while keeping a TCP session open and verify both old-session traffic and new connections. A real destination decodes PROXY v1/v2 and verifies the client's source metadata. The namespace suite also removes duplicate legacy rules and a peer-matched Simple GRE interface while checking unrelated rules survive. Service operations in cleanup tests are stubbed; actual systemd boot/reload ordering still needs target-host rollout tests. Unit tests mock sysctl files, test partial apply recovery, drift preservation, unknown legacy refusal and failed deletion retaining persistence; they never change host sysctls.

Form regressions exercise numbered choices, cancellation before any mutation, automatic names, split/combined targets, IPv6, port batches, ID allocation, preserving unrelated engines and edit options, duplicate targets and wildcard self-loop rejection. Namespace tests exercise the new wildcard HAProxy/Realm listeners on loopback and an actual namespace interface; PTY tests exercise real terminal dimensions and color output.

Header regressions cover public/local separation behind NAT, untruncated IPv6, small/large terminal layouts, default-interface selection, invalid or timed-out metadata responses, sanitized external text and memory-only caching. Mock external requests; tests must not geolocate the developer's machine. A real PTY checks the interactive lookup gate, explicit refresh and disabling lookup; previews use documentation-only example addresses.

## Rollout requirements

Still test two-server reboot persistence, systemd sandbox permissions, UFW/Docker policies, provider GRE/UDP filtering, IPv6 RA/routing, asymmetric return paths, MTU/large packets, certificates, multiple destinations and failure/recovery with sessions. Benchmark throughput, packets/s, connections/s, latency/jitter and RAM/CPU on real workloads before capacity claims.

## Release

Update English README.md, Persian README.fa.md, affected docs and changelog. Persian sentences/headings start with Persian words and code blocks remain left-to-right. Keep reciprocal language links. Bump `GTM_VERSION` in `src/core.sh`; the build header and legacy logo derive from it. Rebuild and check. Confirm `git diff -- gre-stable.sh` is empty. Do not advertise unimplemented WireGuard link provisioning, GRE-over-UDP, hostname targets or HTTP CONNECT tcpmux.

## UX references

The numbered choices and direct engine-specific workflows were reviewed in [Musixal HAProxy](https://github.com/Musixal/HAProxy), [Musixal Rathole-Tunnel](https://github.com/Musixal/Rathole-Tunnel), [Gost-Manager](https://github.com/Sir-Adnan/Gost-Manager) and [Realm-Tunnel-Manager](https://github.com/Sir-Adnan/Realm-Tunnel-Manager). They are visual/workflow references; the local forms and backend ownership/lifecycle implementation remain this repository's code.

## Version policy

The modular manager starts at v1.0.1. Use MAJOR.MINOR.PATCH: patch for compatible fixes, minor for compatible features, major for breaking changes. Historical v13.x releases keep their original numbers. State schema version is independent of manager version.
