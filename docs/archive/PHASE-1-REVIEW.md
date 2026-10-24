# Phase 1 completion report

> Historical implementation review. Describes its recorded milestone, not current installation instructions. Start with the [current guides](../README.md).

## Scope and status

Phase 1 implements interaction corrections, responsive/RTL presentation and the traffic-page redesign. Subsequent phases remain gated by the user's next instruction. This work is an unreleased source change; the existing v1.3.0 release archive is not silently replaced. No production VPS was modified.

## Findings and corrections

| Finding | Correction |
| --- | --- |
| Switches/checkboxes appeared unresponsive | Match Radix `data-state` attributes rather than unrelated checked/open selectors; provide visible switch movement and partial-selection indicators |
| Draft collection settings looked like applied state | Keep the draft form separate from the saved-state badge; require explicit save and expose failures |
| An empty subset could be confused with all resources | Block enabled empty-subset submissions; the API's empty ID list explicitly means all resources |
| `F000003 · nftables` was ambiguous for a HAProxy tunnel | Show actual engine next to the connection; explain internal ID and accounting method in contextual help |
| Dedicated engine forms could select unrelated engines | Limit HAProxy/Realm creation pages to their engine; forwarding offers only kernel forwarding engines |
| Combined destination input could be normalized halfway through typing | Keep raw input during editing and split supported `IP:port` notation on blur |
| Names were hidden in advanced settings | Expose optional forward/relay names in the main form and retain automatic defaults |
| Numbers and technical strings forced whole blocks LTR | Localize display values and keep block alignment logical; isolate technical IP/port/code values |
| Small controls and narrow forms were difficult on mobile | Increase input/touch sizing, improve destination layout, use reachable form footers and the shadcn mobile sidebar |
| Long explanations crowded forms | Add hover/focus action labels and question-mark help that also opens by click/tap |

The application uses Vazirmatn throughout. The original Nettinx color sources remain unchanged, including their documented contrast limitations. The header exposes light/dark/system selection. The traffic chart is a lazy-loaded shadcn/Recharts Area chart; its state/API handling and bounded history helpers are separate modules.

## Validation

- Frontend: clean dependency installation, TypeScript/Vite build, lint, formatting and four Node tests passed. The dependency audit reported no vulnerabilities at the time of validation.
- Existing Python suite: 83 tests passed under Linux/WSL, including both PTY checks. Windows also passed with the two expected Unix-PTY skips.
- Go: `go test -race ./...` and `go vet ./...` passed. Bash bundle freshness, ShellCheck and `git diff --check` passed.
- Browser: real Chromium interactions covered login, a dedicated HAProxy form, character-by-character combined destination input, native preset selection, mouse/Space switch toggling, automatic naming, creation/review, partial row selection, hover tooltips, click/tap help and persistence of saved collection settings in the demo backend.
- Browser layouts: overview and traffic views were checked for document-level horizontal overflow at 320, 360, 390, 768 and 1440 pixels. The form was checked at 390 pixels. Persian RTL, English LTR and header color-mode changes were exercised.
- Chart/error paths: browser API fixtures supplied two explicitly simulated samples and an HTTP 503. The chart rendered, engine/accounting labels remained distinct, the error was displayed and cleared after recovery. The injected 503 caused the expected browser resource error; no application warning/error was observed before that injection.
- Palette fidelity: existing source-token tests passed for both Nettinx modes. This is not a claim that its known AA contrast failures were resolved.

Screenshots and browser scratch scripts are local ignored artifacts under `output/playwright/` and `.work/`; they are not product configuration or a production traffic measurement.

## Boundaries

- The demo cannot change real networking. This phase does not establish traffic-accounting accuracy on two production VPSs or across a reboot.
- The chart retains at most 60 distinct fetched samples per resource during the current page visit. It does not invent a baseline, persist browser history, poll automatically or aggregate overlapping GRE/forward counters. Persistent history belongs to Phase 5.
- Forward/relay names retain current backend ASCII and length limits. Independent editable GRE/reverse display names require the planned metadata work.
- HTTP/quick installation and the eight-character password option are Phase 2. Secure read-only Nodes/Agents, including a Controller-local Node and optional agent-free local-only use, are Phase 3. Coordinated remote writes are Phase 4. Extended native engine capabilities are Phase 5.
- Maintained documentation is English. The former Persian README is now an English compatibility link. Persian UI strings remain part of the bilingual product; archived legacy code is unchanged.
