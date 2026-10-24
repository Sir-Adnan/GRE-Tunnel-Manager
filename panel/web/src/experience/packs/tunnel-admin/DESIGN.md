# Tunnel Admin

Operators manage ports and server links on desktop and mobile, in Persian RTL or English LTR. Keep common actions visible: add, inspect, edit, select and delete. Use a quiet sidebar, a compact server header, readable tables and review before apply. Locally served Vazirmatn is the application font in both languages, with no Persian letter spacing; JetBrains Mono keeps endpoints readable. Local fonts, restrained borders, semantic tokens and short reduced-motion-aware transitions. Nettinx is the original user-selected default palette; its documented contrast limitations are deliberately preserved. Appearance never changes capabilities or permissions.

## Workspace composition

Preserve the imported palette: paper `#ffffff`, ink `#001a3d`, night `#0a0c10`, surface `#14171d`, orange `#ff791a` (dark) / `#ff810a` (light), and slate `#94a3b8`. Use semantic tokens, not hard-coded copies. Vazirmatn carries labels and headings; monospace is reserved for addresses, ports and configuration. Use 12/14/16/24 px roles, 4/8/12/16/24 px spacing and aligned start edges in both directions.

The distinctive element is the route, not a decorative hero. Connection setup places the listener and destinations side by side on desktop and stacks them on mobile. Keep a compact route summary above the footer. Separate connection fields from advanced controls with tabs, retain drafts between tabs, and review before mutation. Optional names follow required fields. Changed drafts require an explicit discard; unchanged forms close immediately.

```text
Header: current page                         local server / appearance / language
Page:   title + count                       configuration preview / new connection
List:   search + filters
        name | local port | destinations | status | edit / more
Editor: [Connection] [Advanced]
        listener            destinations
        optional name       profile / start after saving
        route summary                         cancel / review
```

One surface should group one task. Avoid redundant headings, nested decorative cards and large action-only footers. Use a direct edit action and a labeled overflow menu for secondary operations. Details share summary/destinations tabs and link to existing configuration and traffic tools without inventing engine capabilities. Navigation and list filters belong in shareable hash URLs so direct links work with the embedded server. Motion explains expansion and confirmation; it never delays an operation or repeats on every row.

Recovery uses a compact source-to-destination route and explicit create/restore tabs. The form owns the primary desktop column; scope/reference information uses a quiet secondary column and collapses into an accessible help control on smaller screens. Keep resource inspection and migration fields together, invalidate review after edits, and separate checking from final confirmation. Never use secret values as decorative content or notification text.
