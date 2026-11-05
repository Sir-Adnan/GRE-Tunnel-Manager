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

For live frontend work, run `go run ./cmd/gtm-panel demo --listen 127.0.0.1:8790` in `panel` and `npm run dev` in `panel/web`. The Vite server proxies `/api` to the demo and presents requests as same-origin there, so the panel's Origin/CSRF checks stay enabled. Restart Vite after moving or deleting modules; its module graph can keep a stale copy.

For workspace changes, check direct hash links and browser back/forward, URL-backed search/status filters, inspection-to-traffic links and the current-server popover. Exercise create/edit/review with multiple destinations, an invalid field in a hidden advanced tab, keep/discard and untouched close. Test copied IPv4/IPv6 and configuration text on HTTP as well as secure contexts. A simulated inventory-refresh failure after a successful mutation must show a warning rather than encourage resubmitting the mutation. Keep simulated CRUD separate from real-server networking checks.

## Shell and networking checks

```bash
python3 -m unittest discover -s tests -v
shellcheck -s bash -S warning -e SC2034 src/{core,server_info,ui,haproxy_routing,haproxy,realm_options,metadata,state,firewall,components,relays,transports,rathole,catalog,inspect,forms,optimize,cleanup,links,reverse_api,pair_api,recovery,api,panel,menus}.sh panel-install.sh node-install.sh
sudo bash tests/linux_namespace.sh
sudo bash tests/component_publish_namespace.sh
git diff --check
```

The authoritative CI commands are in [.github/workflows/checks.yml](../.github/workflows/checks.yml). SC2034 is excluded because modules share public variables. Legacy scripts remain unchanged and are outside the modern-module lint gate.

Namespace tests require Linux namespace capabilities, `ip`, `nft`, `nsenter` and Python 3. Installed optional engines are exercised; tests do not download them. CI installs nftables, iptables, conntrack, HAProxy, socat and ShellCheck. Set `GTM_PANEL_TEST_BINARY` to a matching Linux build to cover setup PTYs and actual panel accounting rather than skipping those optional checks.

The suite creates private parent/child namespaces and veth paths. It checks real TCP/UDP NAT, repeat apply/deletion, rejected preflight preserving traffic, IPv4/IPv6 additional addresses, dual-stack listeners on one port, return routing for an address with its own gateway (strict `rp_filter` in the client namespace models upstream anti-spoofing), maintenance rule refresh keeping established flows and flow reset clearing only the selected forward (needs the `conntrack` CLI; otherwise reported as skipped), keyed GRE, route MSS without increasing a smaller peer MSS, relay failover/reload, PROXY metadata and paired creation. Host networking stays outside the fixture. Cleanup stops test processes. A constrained unit runner replaces systemd; actual service boot/reload behavior still requires disposable real hosts.

## Fixtures and contracts

- Form tests cover numbered choices, cancellation, auto names, endpoint formats, multi-port batches and preservation of unrelated state/options. Header tests mock metadata requests; they must not geolocate the development machine.
- Installer tests redirect system paths and fake accounts/services. They cover version/checksum rejection, lock/config failures and upgrade preservation. Never run host-wide installation fixtures on an ordinary development host.
- Go tests cover real local TLS enrollment, identity separation, revocation/renewal, protocol negotiation, reconnect and bounded reports. Paired operations need stale revision, repeated delivery, restart, expiry and fingerprint-preserving rollback coverage.
- Accounting tests cover cycle baselines, restart/reset, missing counters and revision-checked actions. GRE and forward counters can overlap and must not become a combined total.
- Recovery tests exercise authenticated encryption, tampering/wrong passwords, fresh-target/stale-review checks, paused publication and rollback, preserved IDs/keys/accounting, and real Bash round-trips for FRP/rathole. In the browser, download/upload a Demo backup, inspect migration changes, check the occupied-target blocker, then restore into an empty Demo fixture. Test both locales, mobile widths and reduced motion. Demo export does not invent secrets for simulated GRE/reverse resources; real adapter coverage is in Linux fixtures.
- Before changing a component pin, verify the tagged upstream configuration/CLI and actual archive. A recognized version alone does not establish feature availability or peer compatibility.
- Engine maintenance tests use a private mount namespace to shadow `/usr/local/bin` with temporary fixture files. Verify full staging, retained previous binaries and rollback after the second FRP publication fails; no downloaded test binary is executed. Imported configurations need unknown/lossy syntax, stale-review and complete-state-preservation coverage, plus real native renderer round trips.

Keep LF endings, bounded data contracts and checked operations. Do not source user configuration, introduce runtime module downloads or save UI-filtered state. New-connection defaults must not rewrite existing absent-key semantics.

## Documentation and release

Technical guides are English; [README.fa.md](../README.fa.md) is the Persian quick start. Keep user-facing guides about current behavior, move completed implementation reports to the [archive](archive/README.md), and record changes in the changelog.

Use MAJOR.MINOR.PATCH for application releases; state schemas and Node protocols are versioned independently. Historical v13.x tags keep their original numbers. Follow [Releasing](RELEASING.md) for matched versions, packages and publication. Local tests do not establish public-network reachability, reboot recovery or sustained capacity; see [Operations](OPERATIONS.md#deployment-checks-still-requiring-real-hosts).

## Health and maintenance regressions

`internal/health` tests cover failure/recovery thresholds, outage start times, multi-destination status, latency warnings, removed targets, merged report downtime, local week boundaries (Saturday in a +03:30 zone), retention, revision checks and `/proc` deltas. `internal/maintenance` tests cover local daily/weekly/uptime/interval schedules, missed runs, cancellable notices, the reboot loop guard, cooldown, quiet-traffic waits and timeouts, health durations, refresh applicability, manual runs and persistence. `control/operations_test.go` checks the allowlisted command of each step and the demo simulation. `tests/operations.test.mjs` checks templates, validation, summaries and the report CSV. In the browser, check both pages in both locales and at phone width, a reboot plan's second confirmation, Run now and Cancel on a pending notice.

## Telemetry and quota regressions

`control/host_telemetry_test.go` checks aggregate CPU deltas without guest double-counting, cache cadence, default-route deduplication, IPv6-only routes, missing files and counter/idle-gap resets. `traffic_quota_test.go` checks explicit opt-in, cycle reset, persistence, bidirectional scoped rules and collection-selection guards. Linux root runs additionally execute `TestQuotaKernelStopsEstablishedRelayAndResumes` in a new private network namespace; normal unprivileged runs skip that test. CI compiles its test executable and runs this one isolated fixture with sudo.

Browser checks should cover numeric quota/progress at 320–1920px in both locales/modes, policy-switch prerequisites, policy save/reopen, reset/resume help, dashboard polling pause/resume and no live requests after leaving the dashboard. Simulated UI counters must not be reported as real traffic tests.
