// Menu entries that move one item of an ordered list (components/ReorderList
// and the connection form's destinations). Entries that would not move the
// item are left out, so the menu never offers a dead action.
import {
  ArrowDownToLine,
  ArrowUpToLine,
  ChevronDown,
  ChevronUp,
} from "lucide-react";
import type { MenuAction } from "@/components/ActionMenu";

export function moveActions(
  t: (key: string) => string,
  /** Moves the item by this many places (negative is up). */
  move: (delta: number) => void,
  index: number,
  count: number,
): MenuAction[] {
  const actions: (MenuAction | false)[] = [
    index > 1 && {
      id: "move-top",
      label: t("moveTop"),
      icon: <ArrowUpToLine />,
      onSelect: () => move(-index),
    },
    index > 0 && {
      id: "move-up",
      label: t("moveUp"),
      icon: <ChevronUp />,
      onSelect: () => move(-1),
    },
    index < count - 1 && {
      id: "move-down",
      label: t("moveDown"),
      icon: <ChevronDown />,
      onSelect: () => move(1),
    },
    index < count - 2 && {
      id: "move-bottom",
      label: t("moveBottom"),
      icon: <ArrowDownToLine />,
      onSelect: () => move(count - 1 - index),
    },
  ];
  return actions.filter((action): action is MenuAction => Boolean(action));
}
