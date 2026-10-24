# Phase 2: Installation and browser access

> Historical implementation review. Describes its recorded milestone, not current installation instructions. Start with the [current guides](../README.md).

Status: implemented and validated in source on 2026-10-22. Phase 3 has not started. No new release, tag or live-server deployment was made.

## Delivered behavior

- Quick or custom setup, with short numbered choices. Quick mode generates a 32-character password; custom mode uses hidden confirmation and accepts eight Unicode characters within bcrypt's 72-byte limit.
- Explicit HTTP or default HTTPS, selected/random TCP ports, automatic public-IP discovery when omitted, and literal IPv4/IPv6 or an operator-supplied domain. IPv6 URLs retain brackets. A domain is an address supplied by the operator, not a domain registration/DNS service.
- One-time credential output, stored bcrypt hashes, no password argument/environment option, and local password recovery. `address` prints URL/username without redisplaying a password.
- Listener and cookie policy follow the configured protocol. HTTP and HTTPS use separate cookie names so a stale Secure cookie cannot block HTTP login. Sessions retain HttpOnly/SameSite, exact Origin and CSRF checks; forwarded-protocol headers are not trusted.
- A bilingual HTTP explanation on the login page and accessible connection help in desktop navigation and the mobile sidebar. Vazirmatn, responsive forms and the exact Nettinx palette are retained.
- Reinstallation preserves existing configuration, credentials and certificates. An omitted protocol keeps the old HTTPS behavior. Incoming config validation and initial setup complete before stopping existing services. Version/checksum failures and concurrent installers are rejected.
- Explicit optional engine preinstallation; ordinary setup creates no tunnels or unrelated services. New local-package support allows an updated build to be selected deliberately.

## Modules

`panel/internal/setup` owns setup interaction and bounded one-time discovery. `panel/internal/config` owns protocol/address/password validation and certificate/config persistence. `panel/internal/auth` owns protocol-specific cookies. The existing public server remains unprivileged; the root broker stays on its local Unix socket. This phase adds no Node/Agent endpoint or remote shell capability.

## Verification

- Linux: all 93 Python tests passed with `GTM_PANEL_TEST_BINARY` set, including the isolated installer harness and actual terminal password/recovery tests. Windows: 93 discovered, 12 platform/binary-dependent cases skipped.
- Go: `go test -race ./...` and `go vet ./...` passed under Linux. Tests cover discovery fallback/cancellation/untrusted responses, occupied/random ports, IPv6 URLs, domain SANs, password byte/character limits, existing certificate preservation and old HTTPS configs.
- HTTP: real HTTP/TLS socket tests cover login, logout, cookie policy, wrong Origin/scheme, wrong CSRF and ignored forwarded-protocol headers. Actual Chromium login/logout confirmed cookies for both direct listener protocols.
- Frontend: `npm ci`, production build, lint, formatting, four Node tests and npm audit passed. Chromium checked FA/EN login, Vazirmatn, HTTP explanation, desktop/touch connection help and document width at 320, 360, 390, 768 and 1440 pixels. The selected original palette was not recolored.
- ShellCheck, generated-script check and diff whitespace checks passed. Actual packet/engine regression checks passed in private Linux network namespaces, including optional Go counters and preservation of unrelated rules.

The installer harness redirects a test copy into temporary paths and substitutes accounts/systemd commands; it does not modify the host or prove live systemd deployment. Browser listener tests ran locally without a privileged broker; the expected inventory HTTP 502 was observed after login. TLS browser checks explicitly trusted the local self-signed test certificate. No claim of public CA trust, real VPS rollout, provider reachability, reboot behavior or performance benchmarking follows from these tests.

## Release and operational boundaries

Published v1.3.0 remains unchanged and uses its previous HTTPS-only setup. The new installer keeps that default path compatible and explicitly refuses unsupported new flags on a fresh installation. To exercise the new flow now, build the updated source and select the resulting archives through `--package-dir`; downloading only the installer does not replace the published executable. Setup contract `2` identifies the updated flow independently of the application version.

Release automation now requires the matching version tag and creates a new release without asset clobbering. A future release must synchronize version strings and package a new tag; development archives must never replace existing v1.3.0 assets.

IP discovery reports an outgoing public address and may be unsuitable behind NAT/proxies; an explicit address overrides it. DNS provisioning, ACME renewal, trusted reverse-proxy configuration and universal manual DNAT-port detection are outside this phase. The selected port is checked when setup runs, not reserved until service startup. Unexpected disk/systemd failure after executable replacement still requires operator recovery; there is no atomic host-wide upgrade claim. New config fields require matching binaries when downgrading.

Next phase, only after explicit instruction: the optional versioned Node/Agent contract, secure enrollment and read-only inventory described in [the roadmap](../ROADMAP.md).
