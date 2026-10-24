# Contributor instructions

## Start here

This is a Bash tunnel/forwarding manager with an optional Go web panel. Read the affected modules before editing. Use [Architecture](docs/ARCHITECTURE.md) for boundaries and [Server artifacts](docs/ARTIFACTS.md) for ownership and lifecycle.

- `src/` is the shell source; generate `gre.sh` with `python3 tools/build.py`.
- `panel/internal/` owns Go contracts and control; `panel/web/src/` owns the interface.
- `gre-stable.sh` and scripts in `legacy/` are preserved archives.
- Python, Node.js and compilers are development tools, not managed-server requirements.

## Change contracts

- Keep changes focused and modular. Separate presentation, validation/rendering and system operations. Preserve saved configurations and peer compatibility unless an explicit migration is requested.
- Validate external input before commands or generated configuration. Quote shell variables, use command arrays and checked results; never evaluate configuration as code.
- Mutations must lock, reload complete state, check revisions and preserve unrelated records. A filtered UI list is never the state to save.
- Modify only owned resources through existing backup/recovery paths. Report partial failures. Never flush the host firewall or conntrack table.
- Keep public HTTP unprivileged; privileged work uses allowlisted local broker/Bash operations. Do not add arbitrary command or file endpoints.
- Keep common setup short, defaults clear and advanced options optional. Preserve the selected Nettinx palette, bilingual Persian RTL/English LTR UI, Latin display digits and reduced-motion support. See [Interface conventions](docs/INTERFACE.md).

## Verify and document

- Run `python3 tools/build.py --check`, `python3 -m unittest discover -s tests -v`, and `git diff --check`.
- Run the modern-module ShellCheck command in [.github/workflows/checks.yml](.github/workflows/checks.yml).
- For panel changes: `npm ci && npm run build && npm run lint && npm test` in `panel/web`; `go test -race ./... && go vet ./...` in `panel`.
- For networking changes: `sudo bash tests/linux_namespace.sh` in isolated Linux namespaces. For interface changes, check real browser flows in both locales and mobile/desktop sizes.
- Update affected guides and [Changelog](docs/CHANGELOG.md). Technical documentation is English; `README.fa.md` is the Persian quick start. Distinguish local test evidence from real-server checks.

See [Development](docs/DEVELOPMENT.md) for fixtures and [Releasing](docs/RELEASING.md) for version/package checks. Publish or deploy only when the user requests it.
