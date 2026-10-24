# Interface conventions

The terminal and browser share validated backend contracts, but have separate presentation layers. Keep configuration and system operations outside UI components.

## Terminal

Use the fixed English foreground palette, numbered choices, short prompts and clear defaults. Respect NO_COLOR, non-TTY and dumb terminals. Collect inputs before mutation and show review before installation/application. See [Terminal interface](TERMINAL-UI.md).

## Web panel

- Use the existing Radix/shadcn components and semantic tokens. Preserve Nettinx source colors; its approved dark foreground override applies only to orange primary buttons. Other documented contrast limitations are not waived as passing checks.
- Use local Vazirmatn, Persian RTL/English LTR, Latin display digits and explicit LTR isolation for IPs, ports and code. Motion must respect reduced-motion preferences.
- Keep common fields visible, advanced settings grouped in tabs and contextual help accessible by hover, keyboard and tap. Labels must describe the actual action: relative share is not priority; start after saving controls enabled state.
- Choose tables/cards by available content width. Separate IPv4/IPv6, keep labels beside values and show multiple destinations through accessible disclosure.

## Modal layout

Long dialogs use `DialogContent scrollLayout="body"` with one `DialogBody` between fixed header/footer siblings. The body must establish a positioning context and prevent direct children from shrinking. `Field` also establishes a positioning context: Radix hidden absolute form inputs can otherwise extend the outer scroll area beyond visible content.

Use `FieldGroup columns` for two desktop columns and one mobile column. Code/installer blocks keep intrinsic height, wrap within narrow layouts and remain manually selectable when clipboard APIs are unavailable over HTTP. Avoid nested vertical scrollers.

## Verify interactions

Check actual geometry, not just document overflow: no excess outer modal scroll, visible actions and a reachable final input. Test both locales, light/dark, narrow mobile and wide desktop. Exercise selection, switches, presets, review/apply and traffic actions in the loopback demo. Missing samples remain unavailable; never substitute zero or sum overlapping GRE/forward counters.

See [Development](DEVELOPMENT.md) for automated checks and [Releasing](RELEASING.md) for publication gates.
