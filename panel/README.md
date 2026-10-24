# Web panel

An optional Go panel for local tunnel management, with outbound Agents for multi-server inventory, coordinated GRE/FRP setup and read-only traffic summaries. Tunnel traffic runs independently of the panel.

[Install and upgrade](../docs/WEB-PANEL.md) · [Nodes](../docs/NODES.md) · [Configuration editor](../docs/CONFIGURATION-EDITOR.md) · [Traffic accounting](../docs/TRAFFIC-ACCOUNTING.md)

## Build and preview

Development requires Node 24 and Go 1.27.3. Managed servers use prebuilt packages and need neither toolchain.

```bash
cd panel/web
npm ci
npm run build
cd ..
go build -trimpath -ldflags='-s -w' -o bin/gtm-panel ./cmd/gtm-panel
./bin/gtm-panel demo
```

On Windows, name the executable `bin/gtm-panel.exe`. The loopback demo uses **demo / demo-panel-12345** and cannot run system commands. Those credentials never authenticate to a production installation.

See [Development](../docs/DEVELOPMENT.md) for tests and [Releasing](../docs/RELEASING.md) for packaging. Compiled assets and executables are not committed.

## Boundaries

Public HTTP runs unprivileged; typed privileged operations go through the protected local broker and Bash API. Writes reload complete locked state, check revisions and retain recovery. The editor supports validated adapter fields, not arbitrary files or executable directives.

Feature pages use shared tokens and components. See [Interface conventions](../docs/INTERFACE.md) for palette, typography and responsive layouts; [Architecture](../docs/ARCHITECTURE.md) for module ownership; [Server artifacts](../docs/ARTIFACTS.md) for lifecycle.
