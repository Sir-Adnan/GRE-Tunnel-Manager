# Interface conventions

Settings uses four route-backed tabs: Security & access (default), Appearance, Notifications and Metrics. Existing `section=notifications` and `section=metrics` bookmarks select their tab. Inactive panels stay mounted but hidden so unsaved integration fields are retained in memory while switching tabs. Mobile tabs use two columns and 44 px targets; desktop uses one row. Security begins with browser connection security: actual loaded-certificate metadata, a trust distinction, expiry and a fixed-path reload action. HTTP, self-signed HTTPS and externally issued certificates have separate copy. Certificate commands use the shared wrapping/copy component; keys/PEM never enter the UI. Server DNS labels active global servers and configured values separately and explains local stub addresses. Backup tabs explain off-server downloads, on-server scheduled snapshots and paused restore before their forms. Invalid advanced fields activate their owning controlled tab before focus/validity reporting. A saved connection's later policy failure closes the creation form with partial-success guidance so it cannot invite duplicate creation.

Backup & restore uses separate create/restore tabs and a source-to-destination review. Passwords and file contents stay in transient component/request memory, never route parameters or browser storage. IP/interface edits invalidate the current review until checked again. Show resource summaries, blockers and external-certificate references before a separate confirmation. A successful import explains the paused state and activation steps; partial accounting failure remains visible.

The terminal and browser share validated backend contracts, but have separate presentation layers. Keep configuration and system operations outside UI components.

## Terminal

Use the fixed English foreground palette, numbered choices, short prompts and clear defaults. Respect NO_COLOR, non-TTY and dumb terminals. Collect inputs before mutation and show review before installation/application. See [Terminal interface](TERMINAL-UI.md).

## Web panel

- Use the existing Radix/shadcn components and semantic tokens. **Signal** (Grafana-like) is the user-selected default preset; **Graphite** (Linear-like) and **Aurora** are project presets, and **Nettinx** and **Neutral** remain selectable. Project presets define every status and `*-text` token and must pass the WCAG AA pairs in `panel/web/tests/themes.test.mjs`. Nettinx source colors stay exact; its approved dark foreground override applies only to orange primary buttons, and its documented contrast limitations are not waived as passing checks.
- Typography is preset-independent: local Inter Variable sets Latin text and digits, Persian glyphs fall through to local Vazirmatn, and JetBrains Mono is reserved for addresses, ports and configuration. Persian keeps zero letter spacing and taller lines. Use Persian RTL/English LTR, Latin display digits and explicit LTR isolation for IPs, ports and code.
- Motion is subtle (about 150-260 ms, eased): page sections cascade in, cards lift slightly on hover, live indicators pulse and the selection bar rises. All of it lives in `styles/motion.css` and is removed under `prefers-reduced-motion`. Entry animations must not leave a transform behind (use `backwards` fill), or fixed descendants lose the viewport as their containing block.
- Keep common fields visible, advanced settings grouped in tabs and contextual help accessible by hover, keyboard and tap. Labels must describe the actual action: relative share is not priority; start after saving controls enabled state.
- Choose tables/cards by available content width. Separate IPv4/IPv6, keep labels beside values and show multiple destinations through accessible disclosure.

## Browser workspace

Hash routes (`#/connections?engine=haproxy`, `#/traffic?tab=details&resource=F000001`) support direct links and browser back/forward without server rewrites. `lib/navigation.ts` allowlists pages and maps the v1.3 engine pages (`#/forwarding`, `#/haproxy`, `#/realm`) to the Connections page with an engine filter; `use-panel-route.ts` owns URL subscriptions and rewrites legacy or unknown addresses to the canonical route in place.

Navigation has one model (`components/nav-items.ts`) shared by the sidebar, the mobile bar and the command palette: **Workspace** (Overview, Connections, Traffic), **Network** (Nodes, GRE, Reverse) and **System** (Engines, Backup & restore, Settings). Ctrl/Cmd+K, the sidebar search field or the mobile search button opens the command palette: pages, engine filters, creation per engine, appearance and saved connections. Commands only navigate, open forms or change local preferences; they never apply changes without the normal review. Connection search, status and inspection tabs use query parameters. Replace history for filter typing; push history when opening a connection. Do not put configuration, credentials or tokens in URLs.

`PanelHeader` owns local-server identity, separately copyable addresses and appearance/language controls. Connection management is local; this header must not imply that arbitrary remote operations are available. Nodes separate the server inventory from coordinated connection setup.

The overview is status-first: host identity and one address, four KPI tiles (connections, running services, items needing attention, uptime/load), live telemetry beside a **Needs attention** panel and recent connections with engine shortcuts. `lib/attention.ts` derives attention items from inventory alone: enabled services in a failed or stopped systemd state, and engines that enabled connections need but that are not installed. An empty list is shown as an explicit healthy state.

`ConnectionWorkspace` owns list scope and the engine filter chips (`lib/connection-filters.ts`, with counts); a filtered view also chooses the engine a new connection starts with. `ConnectionTable` owns selection and revision-bearing actions; names open a read-only detail dialog. Each row has an explicit on/off switch and edit; details, configuration, logs and delete use a labeled menu. Bulk actions appear in a floating selection bar (portaled to `<body>`) only while rows are selected, above the mobile navigation on phones. Mobile identity and engine metadata are distinct stacked elements. Balance desktop column widths instead of giving every spare pixel to the name. Search/status filters share a compact row when they fit. The whole-server preview belongs in the toolbar. Do not replace actual runtime status with optimistic health claims.

Configuration imports separate file/text entry from parsed resource review. Show replaced process settings, activation state and generated output before saving. Any draft edit invalidates review. Engine maintenance displays installed, upstream and verified/candidate versions separately; checking is read-only, updating requires its own confirmation. The header's appearance button opens one popover with the color mode and the preset list. Settings shows presets as cards with light and dark miniatures painted from registry swatches, default first.

`useConnectionDraft` retains a private copy of the opened record. `ConnectionBasics`, `ConnectionAdvanced` and `ConnectionReview` render distinct stages. Required ports precede optional names; desktop entrance/destination panels stack on mobile. Tabs retain their controls so hidden invalid fields are revealed and focused before review. Network validation and mutations remain authoritative on the server.

Changed connection, GRE/reverse and configuration drafts use `use-discard-changes` for close/refresh protection; unchanged views close immediately. Drafts remain in memory and are not saved in browser storage. Successful save bypasses discard confirmation. Sonner notifications distinguish success, failure and a completed mutation whose inventory refresh failed. Mobile notifications sit above bottom navigation. Use concise visible errors; help tips must never hide essential failures or destructive-action warnings.

## Modal layout

Long dialogs use `DialogContent scrollLayout="body"` with one `DialogBody` between fixed header/footer siblings. The body must establish a positioning context and prevent direct children from shrinking. `Field` also establishes a positioning context: Radix hidden absolute form inputs can otherwise extend the outer scroll area beyond visible content.

Use `DialogFooter layout="summary"` for a route summary followed by action buttons. Its mobile order is explicit; do not override the standard action footer's reversed column layout through competing utility classes.

Use `FieldGroup columns` for two desktop columns and one mobile column. Code/installer blocks keep intrinsic height, wrap within narrow layouts and remain manually selectable. Avoid nested vertical scrollers.

Copy actions share `lib/clipboard.ts`: prefer the Clipboard API, then attempt a user-initiated selection copy for HTTP or denied API access. Temporary fields stay inside the active modal to respect its focus trap, are removed after copying and restore focus/selection. Only report success after an API confirmation; otherwise show a bilingual manual-copy instruction. Never put enrollment codes, tokens or configuration contents in notifications.

## Frontend modules

- State: `lib/use-session.ts`, `lib/use-inventory.ts` (load and optional 30 s refresh, paused during jobs), `lib/use-operations.ts` (job runner and result dialog) and `lib/preferences.ts` (validated, migrated browser preferences). `App.tsx` composes them.
- Polling: every periodic request uses `lib/use-poll.ts`, which runs only while the page is visible, never overlaps runs, aborts on hide, unmount or timeout and always calls the latest callback.
- Messages: `lib/i18n/messages/<feature>.ts` hold `[English, Persian]` pairs checked by `satisfies Messages`; a key lives in exactly one module and Persian text uses Latin digits (`tests/i18n.test.mjs`). Shared words live in `common.ts`.
- Styles: `index.css` only imports; `styles/base.css` (typography, elevation), `shell.css` (sidebar, header, mobile bar), `components.css` (patterns), `operations.css` (health and maintenance), `forms.css` (dialogs and editor) and `motion.css`. Colors come only from style tokens.
- Preferences migrate once from `gtm.preferences.v1` to `v2`. v1 always stored the style, so its stored Nettinx (the old default) becomes Signal; any choice saved afterwards, Nettinx included, is kept.

## Verify interactions

Check actual geometry, not just document overflow: no excess outer modal scroll, visible actions and a reachable final input. Test both locales, light/dark, narrow mobile and wide desktop. Exercise selection, switches, presets, review/apply and traffic actions in the loopback demo. Missing samples remain unavailable; never substitute zero or sum overlapping GRE/forward counters.

See [Development](DEVELOPMENT.md) for automated checks and [Releasing](RELEASING.md) for publication gates.

Dashboard activity uses one compact four-metric region with Latin values and directional network labels. A pause control and 5/15-second cadence keep polling explicit. Unavailable readings use a dash, never a fabricated zero. Quota presentation shares `QuotaStatus` between mobile rows, desktop cells and details; show the numeric cap, current usage/direction and the last successfully applied blocking status. Automatic pause is opt-in with sampling, scope and resume help.

Destination cards separate reorder/index/remove controls from the editable field grid. Below a 30 rem card width the address spans the whole row and port/share sit side by side; wider cards align all three controls. Shared text/choice label rows reserve the same height, including optional help. Phone connection cards give listener and destination their own labeled rows. Host/port values can wrap at their boundary, while a port stays intact; long IPv6/domain values can wrap. Do not reduce input text below 16 px on phones or disable browser zoom to compensate for a layout problem. CSS text-size-adjust controls automatic inflation while preserving user zoom. Optional background help uses the shared hover/focus/tap `HelpTip`; errors, current state and destructive consequences remain visible.
