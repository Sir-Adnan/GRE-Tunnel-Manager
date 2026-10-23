# Optional Go web panel

Manage local tunnels in a browser, or add optional outbound Agents for multi-server inventory, coordinated GRE/FRP creation and read-only traffic snapshots. The panel embeds its built interface and runs independently of tunnel traffic.

Start with the [installation guide](../docs/WEB-PANEL.md). The project quick start is available in [English](../README.md) and [Persian](../README.fa.md).

## Build and preview

Development requires Node 24 and Go 1.27.3. Managed servers use prebuilt packages and need neither compiler nor Node.js.

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

On Windows, name the executable `bin/gtm-panel.exe`; use a Linux development environment for race tests when a local C toolchain is unavailable. The loopback demo uses **demo / demo-panel-12345**, labels simulated data and never runs system commands. Demo credentials do not authenticate to production installations.

From the repository root, `python3 tools/package_panel.py` creates Linux amd64/arm64 archives and `SHA256SUMS` after the frontend build. Compiled assets and binaries are not committed.

## Release packages

Version **v1.3.1** includes quick HTTP/HTTPS setup, Nodes/Agents, coordinated GRE/FRP creation, optional remote traffic, advanced engine profiles, traffic cycles and the configuration viewer/editor. Published v1.3.0 assets remain unchanged. A source checkout does not replace an installed binary; use the matching release installer or an explicit local package directory.

The setup contract is `2`; inventory, paired operations and optional traffic each retain separate protocol/contract checks. See [Nodes](../docs/NODES.md), [paired connections](../docs/PAIRED-CONNECTIONS.md), [remote traffic](../docs/REMOTE-TRAFFIC.md), [configuration editing](../docs/CONFIGURATION-EDITOR.md) and [profiles](../docs/CONNECTION-PROFILES.md).

## Development boundaries

- Public HTTP/HTTPS runs unprivileged. Closed operations go through a protected local Unix broker and the Bash API; never add shell-command, arbitrary-file or unrestricted native-config endpoints. The configuration editor imports only validated adapter fields and reuses the existing update transaction.
- Forwarding writes reload complete state under its existing lock, compare revisions, validate natively where supported and retain recovery paths. Presentation filters are not saved state.
- Feature modules share semantic tokens and the allowlisted experience registry. Keep the selected Nettinx fills/source tokens intact. Its approved dark foreground applies only to orange buttons; other known contrast findings remain documented. Locale controls direction and Latin numerals independently of theme.
- The overview has a dedicated bounded summary component; the management table owns selection/actions. Keep transport and system operations out of presentation components.
- Optional Agent traffic reporting requires `--traffic` installation and separate local collection enablement. It adds no public listener or new collector service. General remote reset/configuration is outside this profile.

For module ownership and recovery details, read [Architecture](../docs/ARCHITECTURE.md), [server artifacts](../docs/ARTIFACTS.md), [routing](../docs/HAPROXY-ROUTING.md) and [traffic accounting](../docs/TRAFFIC-ACCOUNTING.md).
