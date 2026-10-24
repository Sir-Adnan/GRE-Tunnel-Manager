# GRE Tunnel Manager v1.3.2

This update fixes oversized modal scrolling, simplifies setup and reorganizes the guides around installation and everyday use.

## Interface and setup

- Fix nested modal scrolling and hidden Radix form inputs extending the dialog. Keep actions reachable, compact desktop field groups and single-column mobile layouts across connection, GRE/reverse, configuration and Node forms.
- Offer three short setup presets per engine (21 total), with advanced controls still available. Explain relative share, start-after-save and read-only configuration preview.
- Make Add server open a three-step Controller/Agent guide when setup is needed. Keep commands readable and IPv4/IPv6 addresses separate; browser HTTP remains independent of the TLS Agent listener.
- Add a paginated traffic list with search, filters and row actions for advisory quotas, cycle reset and supported manual stop. Keep details/history and collection settings in separate tabs.
- Fix Demo revision/status updates so newly created and changed records remain inspectable.

## Defaults and compatibility

New HAProxy connections use `maxconn=100000`, no per-target cap and logging off; new Realm connections also start with logging off. Explicit user values win. Saved configurations and legacy absent-key behavior are preserved. The ceiling is not a capacity guarantee; size it for the host and workload. No host-wide tuning or automatic quota cutoff is added.

The selected Nettinx palette, bilingual interface, Latin display digits and reduced-motion support are retained. Node protocols, identities and operation/traffic opt-ins remain compatible. General remote configuration/accounting writes remain outside the supported profile.

## Documentation and upgrade

Rewrite the English/Persian quick starts, shorten contributor instructions and current guides, add a release checklist and archive completed implementation reviews. Keep detailed recovery and security guidance linked from the quick start.

Run the matching installer to upgrade, then refresh the browser for the embedded interface. Existing credentials, certificates and tunnel settings are preserved. Linux amd64/arm64 packages include the executable, frontend and matching Bash helper; verify `SHA256SUMS`. Managed servers need no Node.js, Python, compiler or database server.

Verification includes Bash/Python, modern ShellCheck, frontend build/lint/tests, Go race/vet, isolated networking and responsive browser flows. Public VPS connectivity, real systemd/reboots, native arm64 execution and sustained capacity remain deployment checks. Previous release assets are unchanged.
