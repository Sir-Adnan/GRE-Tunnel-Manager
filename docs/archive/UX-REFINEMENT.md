# Form layout and setup clarity

> Historical implementation review. Describes its recorded milestone, not current installation instructions. Start with the [current guides](../README.md).

Status: implemented after v1.3.1 and included in v1.3.2. Current conventions are in [Interface conventions](../INTERFACE.md).

## Layout contract

Long forms use `DialogContent scrollLayout="body"`, a single `DialogBody`, and fixed header/footer siblings. The body establishes a positioning context, scrolls within the viewport and prevents direct children from shrinking. `Field` also establishes a positioning context for Radix's hidden form controls. An absolutely positioned hidden checkbox can otherwise enlarge the outer dialog scroll area even when the visible form is inside a smaller scroller.

`FieldGroup columns` creates two desktop columns and one on mobile. IP/port values retain explicit direction; labels and action placement follow the locale. Commands use intrinsic-height blocks, wrap within narrow layouts and remain manually selectable on HTTP.

Connection forms separate advanced limits/timeouts, network/logging and HAProxy routing/health. GRE, reverse, pairing, configuration inspection, Node details and onboarding share the bounded body. Review-before-apply remains in place.

## Behavior decisions

- Three short setup presets per engine; all supported advanced controls remain available.
- New HAProxy: 100000 maximum connections, no per-target cap, connection logging off. New Realm: logging off. Existing records retain their exact semantics. This adds no host-wide tuning or automatic encryption.
- Agent management remains optional. A disabled Controller routes Add server to setup guidance. Browser HTTP does not disable the separate TLS Agent listener.
- Traffic list actions reuse captured identity/revision dialogs. Missing samples remain unavailable; overlapping GRE/forward traffic is never summed. Quotas remain advisory.
- Relative share is a weight, not priority. Start after saving controls the saved enabled state. Whole-server configuration preview is read-only.
- The imported Nettinx palette is preserved. Brief control/dialog/tab motion respects reduced-motion preferences.

## Verification

Check visible geometry, not just document overflow: no excess outer dialog scroll range, headings/actions within the viewport, readable code blocks and a reachable final input. Exercise both directions, light/dark, narrow mobile and wide desktop across forward, GRE/reverse and Node dialogs. Exercise traffic actions against demo data without changing host networking.

Run the checks in AGENTS.md. Namespace tests use isolated Linux networking. Public VPS capacity, reboot/systemd deployment and real VPN sessions remain operator checks; no resource or throughput benchmark is implied.

Local verification for this follow-up:

- Frontend clean install, production build, lint, formatting and 8 unit tests passed.
- All 117 Python tests passed with a matching Linux development binary; generated-script checks, modern-module ShellCheck and isolated namespace tests passed.
- Go race tests and vet passed; the updated Demo revision/import regression also passed on Linux with the race detector.
- Browser coverage included 132 layout cases across both locales and light/dark, including 96 modal cases with zero excess outer scroll range. A final 12-check pass covered preset selection, command typography and responsive layouts after polish.
- Browser operations verified creation defaults, disabled creation, configuration inspection, affinity setup, HTTP Controller guidance, IPv6 command construction, per-row quotas/reset/stop isolation and details navigation. No production host was changed.
