# Development

Read [AGENTS.md](../AGENTS.md) for change contracts, [Architecture](ARCHITECTURE.md) for module boundaries and [Server artifacts](ARTIFACTS.md) before changing resource lifecycle.

## Build

Shell builds require Python 3 and use only its standard library. Edit `src/`, then generate the standalone script:

```bash
python3 tools/build.py
python3 tools/build.py --check
```

The panel uses Node 24 and Go 1.27.3 for development. Managed servers use the prebuilt executable and matching Bash helper; they need neither compiler nor Node.js.

```bash
cd panel/web
npm ci
npm run build
npm run lint
npm test
npm run format:check
cd ..
go test -race ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o bin/gtm-panel ./cmd/gtm-panel
./bin/gtm-panel demo
```

The demo is loopback-only, uses **demo / demo-panel-12345**, labels simulated state and cannot execute system commands. On Windows, name the executable `gtm-panel.exe`; use Linux for race tests if no C toolchain is available locally. Browser checks cover both locales, color modes and mobile/desktop widths; see [Interface conventions](INTERFACE.md).

## Shell and networking checks

```bash
python3 -m unittest discover -s tests -v
shellcheck -s bash -S warning -e SC2034 src/{core,server_info,ui,haproxy_routing,haproxy,realm_options,metadata,state,firewall,relays,transports,rathole,catalog,inspect,forms,tuning,cleanup,links,reverse_api,pair_api,api,panel,menus}.sh panel-install.sh node-install.sh
sudo bash tests/linux_namespace.sh
git diff --check
```

The authoritative CI commands are in [.github/workflows/checks.yml](../.github/workflows/checks.yml). SC2034 is excluded because modules share public variables. Legacy scripts remain unchanged and are outside the modern-module lint gate.

Namespace tests require Linux namespace capabilities, `ip`, `nft`, `nsenter` and Python 3. Installed optional engines are exercised; tests do not download them. CI installs nftables, iptables, HAProxy, socat and ShellCheck. Set `GTM_PANEL_TEST_BINARY` to a matching Linux build to cover setup PTYs and actual panel accounting rather than skipping those optional checks.

The suite creates private parent/child namespaces and veth paths. It checks real TCP/UDP NAT, repeat apply/deletion, rejected preflight preserving traffic, keyed GRE, route MSS without increasing a smaller peer MSS, relay failover/reload, PROXY metadata and paired creation. Host networking stays outside the fixture. Cleanup stops test processes. A constrained unit runner replaces systemd; actual service boot/reload behavior still requires disposable real hosts.

## Fixtures and contracts

- Form tests cover numbered choices, cancellation, auto names, endpoint formats, multi-port batches and preservation of unrelated state/options. Header tests mock metadata requests; they must not geolocate the development machine.
- Installer tests redirect system paths and fake accounts/services. They cover version/checksum rejection, lock/config failures and upgrade preservation. Never run host-wide installation fixtures on an ordinary development host.
- Go tests cover real local TLS enrollment, identity separation, revocation/renewal, protocol negotiation, reconnect and bounded reports. Paired operations need stale revision, repeated delivery, restart, expiry and fingerprint-preserving rollback coverage.
- Accounting tests cover cycle baselines, restart/reset, missing counters and revision-checked actions. GRE and forward counters can overlap and must not become a combined total.
- Before changing a component pin, verify the tagged upstream configuration/CLI and actual archive. A recognized version alone does not establish feature availability or peer compatibility.

Keep LF endings, bounded data contracts and checked operations. Do not source user configuration, introduce runtime module downloads or save UI-filtered state. New-connection defaults must not rewrite existing absent-key semantics.

## Documentation and release

Technical guides are English; [README.fa.md](../README.fa.md) is the Persian quick start. Keep user-facing guides about current behavior, move completed implementation reports to the [archive](archive/README.md), and record changes in the changelog.

Use MAJOR.MINOR.PATCH for application releases; state schemas and Node protocols are versioned independently. Historical v13.x tags keep their original numbers. Follow [Releasing](RELEASING.md) for matched versions, packages and publication. Local tests do not establish public-network reachability, reboot recovery or sustained capacity; see [Operations](OPERATIONS.md#deployment-checks-still-requiring-real-hosts).
