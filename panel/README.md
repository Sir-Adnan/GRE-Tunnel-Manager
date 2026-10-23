# Optional Go web panel

Production installation and supported features: [Web panel guide](../docs/WEB-PANEL.md).

Build locally (Node 24 and Go 1.27.3):

```bash
cd panel/web
npm ci
npm run build
cd ..
go test -race ./...
go vet ./...
go build -trimpath -ldflags='-s -w' -o bin/gtm-panel ./cmd/gtm-panel
./bin/gtm-panel demo
```

The loopback-only demo uses `demo` / `demo-panel-12345`, clearly labels simulated data, and never runs system commands. On Windows, build `bin/gtm-panel.exe`. Production defaults to HTTPS and supports explicitly selected HTTP in the updated source; credentials are user-created or securely generated during setup; the demo login cannot authenticate to a production installation.

`python3 tools/package_panel.py` from the repository root creates Linux amd64/arm64 archives and SHA256SUMS after the frontend build. No compiled assets or binaries are checked into Git.

Frontend feature modules use the semantic design tokens and allowlisted experience registry. The default Nettinx source is recorded in `web/src/experience/sources/nettinx.json`. Its original palette is preserved at the user's request, including known contrast failures documented in the panel guide. A neutral alternative is installed. Do not silently recolor the source. Locale controls direction; themes never control capabilities or permissions.

Runtime modules: `config`, `auth`, `model`, `control`, `httpapi`, and embedded `ui`. The privileged broker's request schema is closed; never add a shell-command or arbitrary-file endpoint. Mutations of forwarding state go through the Bash API, its shared lock, full-state reload, native checks and recovery path.

Current source includes unreleased installation changes. `gtm-panel setup-version` reports setup contract `2`; published v1.3.0 does not provide that contract. Use `panel-install.sh --package-dir panel/bin` for explicit local-package validation. Published packages are never silently replaced by a source checkout.

Optional multi-server inventory and explicitly enabled leased GRE/FRP pairing is implemented in current source under `internal/nodes`, using a separate TLS-only Controller endpoint and outbound Agents. It is independent of browser HTTP/HTTPS. See [Node guide](../docs/NODES.md); published v1.3.0 lacks this feature.
