# Tunnel Admin

Operators manage ports and server links on desktop and mobile, in Persian RTL or English LTR. Keep common actions visible: add, inspect, edit, select and delete. Use a quiet sidebar with a search/command entry, a compact server header, readable tables and review before apply. Inter sets Latin text and digits and locally served Vazirmatn sets Persian, with no Persian letter spacing; JetBrains Mono keeps endpoints readable. Local fonts, hairline borders, quiet elevation, semantic tokens and short reduced-motion-aware transitions. Signal is the user-selected default preset; Graphite, Aurora, Nettinx and Neutral stay selectable. Nettinx keeps its exact palette and documented contrast limitations. Appearance never changes capabilities or permissions.

## Workspace composition

| Preset           | Character                                                  | Dark base / surface / accent      |
| ---------------- | ---------------------------------------------------------- | --------------------------------- |
| Signal (default) | Dense observability, in the spirit of Grafana; 6 px radius | `#111217` / `#181b1f` / `#3d71d9` |
| Graphite         | Calm neutral focus, in the spirit of Linear; 10 px radius  | `#0c0d0f` / `#131416` / `#5e6ad2` |
| Aurora           | Navy operations room with a teal accent; 12 px radius      | `#070b14` / `#0d1422` / `#2dd4bf` |
| Nettinx          | The imported orange-on-navy palette, kept exact            | `#0a0c10` / `#14171d` / `#ff791a` |

Use semantic tokens, not hard-coded copies; text in a hue uses its `*-text` token. Type roles are 11/12/14/16/26 px with semibold headings and tabular figures for metrics. Use 4/8/12/16/24 px spacing and aligned start edges in both directions.

The distinctive element is the route, not a decorative hero. Connection setup places the listener and destinations side by side on desktop and stacks them on mobile. Keep a compact route summary above the footer. Separate connection fields from advanced controls with tabs, retain drafts between tabs, and review before mutation. Optional names follow required fields. Changed drafts require an explicit discard; unchanged forms close immediately.

```text
Sidebar: logo / search (Ctrl K) / Workspace, Network, System / server card
Header:  current page                     search (mobile) / server / appearance / refresh / language
Home:    host + status + address          see all / new connection
         4 KPI tiles / live telemetry | needs attention / recent connections
Page:    title + help                     preview / import / new connection
Filter:  [All n] [Port forwarding n] [HAProxy n] [Realm n]
List:    search + status
         name | local port | destinations | status | on/off, edit, more
         floating selection bar while rows are selected
Editor: [Connection] [Advanced]
        listener            destinations
        optional name       profile / start after saving
        route summary                         cancel / review
```

One surface should group one task. Avoid redundant headings, nested decorative cards and large action-only footers. Keep an explicit on/off switch and edit visible; use a labeled overflow menu for details, configuration, logs and delete. Stack mobile names and engine metadata explicitly; balance table widths on desktop. Compact search and status controls share a row when space permits. Appearance is one header popover (mode and preset) at every width. Details and navigation use existing shareable hash URLs. Motion explains expansion and confirmation; it never delays operations or repeats on every row.

Recovery uses a compact source-to-destination route and explicit create/restore tabs. The form owns the primary desktop column; scope/reference information uses a quiet secondary column and collapses into an accessible help control on smaller screens. Keep resource inspection and migration fields together, invalidate review after edits, and separate checking from final confirmation. Never use secret values as decorative content or notification text.
