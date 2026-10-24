# Interface conventions

Backup & restore uses separate create/restore tabs and a source-to-destination review. Passwords and file contents stay in transient component/request memory, never route parameters or browser storage. IP/interface edits invalidate the current review until checked again. Show resource summaries, blockers and external-certificate references before a separate confirmation. A successful import explains the paused state and activation steps; partial accounting failure remains visible.

The terminal and browser share validated backend contracts, but have separate presentation layers. Keep configuration and system operations outside UI components.

## Terminal

Use the fixed English foreground palette, numbered choices, short prompts and clear defaults. Respect NO_COLOR, non-TTY and dumb terminals. Collect inputs before mutation and show review before installation/application. See [Terminal interface](TERMINAL-UI.md).

## Web panel

- Use the existing Radix/shadcn components and semantic tokens. Preserve Nettinx source colors; its approved dark foreground override applies only to orange primary buttons. Other documented contrast limitations are not waived as passing checks.
- Use local Vazirmatn, Persian RTL/English LTR, Latin display digits and explicit LTR isolation for IPs, ports and code. Motion must respect reduced-motion preferences.
- Keep common fields visible, advanced settings grouped in tabs and contextual help accessible by hover, keyboard and tap. Labels must describe the actual action: relative share is not priority; start after saving controls enabled state.
- Choose tables/cards by available content width. Separate IPv4/IPv6, keep labels beside values and show multiple destinations through accessible disclosure.

## Browser workspace

Hash routes (`#/haproxy`, `#/traffic?tab=details&resource=F000001`) support direct links and browser back/forward without server rewrites. `lib/navigation.ts` allowlists pages; `use-panel-route.ts` owns URL subscriptions. Connection search, status and inspection tabs use query parameters. Replace history for filter typing; push history when opening a connection. Do not put configuration, credentials or tokens in URLs.

`PanelHeader` owns local-server identity, separately copyable addresses and appearance/language controls. Connection management is local; this header must not imply that arbitrary remote operations are available. Nodes separate the server inventory from coordinated connection setup.

`ConnectionWorkspace` owns list scope. `ConnectionTable` owns selection and revision-bearing actions; connection names open a read-only detail dialog and direct edit remains visible. Secondary actions use labeled Radix menus. The whole-server preview belongs in the toolbar, not a large list footer. Do not replace actual runtime status with optimistic health claims.

`useConnectionDraft` retains a private copy of the opened record. `ConnectionBasics`, `ConnectionAdvanced` and `ConnectionReview` render distinct stages. Required ports precede optional names; desktop entrance/destination panels stack on mobile. Tabs retain their controls so hidden invalid fields are revealed and focused before review. Network validation and mutations remain authoritative on the server.

Changed connection, GRE/reverse and configuration drafts use `use-discard-changes` for close/refresh protection; unchanged views close immediately. Drafts remain in memory and are not saved in browser storage. Successful save bypasses discard confirmation. Sonner notifications distinguish success, failure and a completed mutation whose inventory refresh failed. Mobile notifications sit above bottom navigation. Use concise visible errors; help tips must never hide essential failures or destructive-action warnings.

## Modal layout

Long dialogs use `DialogContent scrollLayout="body"` with one `DialogBody` between fixed header/footer siblings. The body must establish a positioning context and prevent direct children from shrinking. `Field` also establishes a positioning context: Radix hidden absolute form inputs can otherwise extend the outer scroll area beyond visible content.

Use `DialogFooter layout="summary"` for a route summary followed by action buttons. Its mobile order is explicit; do not override the standard action footer's reversed column layout through competing utility classes.

Use `FieldGroup columns` for two desktop columns and one mobile column. Code/installer blocks keep intrinsic height, wrap within narrow layouts and remain manually selectable. Avoid nested vertical scrollers.

Copy actions share `lib/clipboard.ts`: prefer the Clipboard API, then attempt a user-initiated selection copy for HTTP or denied API access. Temporary fields stay inside the active modal to respect its focus trap, are removed after copying and restore focus/selection. Only report success after an API confirmation; otherwise show a bilingual manual-copy instruction. Never put enrollment codes, tokens or configuration contents in notifications.

## Verify interactions

Check actual geometry, not just document overflow: no excess outer modal scroll, visible actions and a reachable final input. Test both locales, light/dark, narrow mobile and wide desktop. Exercise selection, switches, presets, review/apply and traffic actions in the loopback demo. Missing samples remain unavailable; never substitute zero or sum overlapping GRE/forward counters.

See [Development](DEVELOPMENT.md) for automated checks and [Releasing](RELEASING.md) for publication gates.
