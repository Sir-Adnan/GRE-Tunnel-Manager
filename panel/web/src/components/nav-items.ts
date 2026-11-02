import {
  Activity,
  Archive,
  ArrowLeftRight,
  Boxes,
  Gauge,
  Layers3,
  Network,
  Server,
  Settings2,
} from "lucide-react";
import type { LucideIcon } from "lucide-react";
import type { Page } from "@/lib/navigation";

export type NavItem = { id: Page; icon: LucideIcon };

/** One navigation model for the sidebar, the mobile bar and the command palette. */
export const navGroups: { title: string; items: NavItem[] }[] = [
  {
    title: "workspace",
    items: [
      { id: "overview", icon: Gauge },
      { id: "connections", icon: Layers3 },
      { id: "traffic", icon: Activity },
    ],
  },
  {
    title: "networkGroup",
    items: [
      { id: "nodes", icon: Server },
      { id: "gre", icon: Network },
      { id: "reverse", icon: ArrowLeftRight },
    ],
  },
  {
    title: "systemGroup",
    items: [
      { id: "components", icon: Boxes },
      { id: "backups", icon: Archive },
      { id: "settings", icon: Settings2 },
    ],
  },
];

export const navItems = navGroups.flatMap((group) => group.items);
/** The bottom bar on phones; everything else is one tap away in "More". */
export const mobileItems = navItems.filter((item) =>
  ["overview", "connections", "traffic", "nodes"].includes(item.id),
);
