// One connection as a card (phones and narrow panes). Quiet by default: the
// status, the route and the everyday actions. A long press or the toolbar's
// "Select" turns every card into a selectable one; reordering has its own
// list (components/ReorderList), so no card carries a drag handle.
import type { ReactNode } from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { EngineGlyph, Status } from "@/components/shared";
import { SwipeActions, type SwipeAction } from "@/components/SwipeActions";
import { useLongPress } from "@/hooks/use-long-press";
import { engineName } from "@/lib/format";
import { useT } from "@/lib/i18n";
import type { Connection } from "@/lib/api";
import type { Tone } from "@/lib/connection-tone";
import { RouteChain, StatusChip } from "./RouteChain";

export function ConnectionCard({
  row,
  tone,
  status,
  health,
  badges,
  actions,
  swipe,
  selecting,
  selected,
  onSelectedChange,
  onStartSelecting,
  onOpen,
}: {
  row: Connection;
  tone: Tone;
  status: string;
  /** The monitoring dot. */
  health: ReactNode;
  badges: ReactNode;
  /** The footer's switch, edit and menu. */
  actions: ReactNode;
  swipe: { start: SwipeAction[]; end: SwipeAction[] };
  selecting: boolean;
  selected: boolean;
  onSelectedChange: (selected: boolean) => void;
  /** A long press: enter selection mode with this card selected. */
  onStartSelecting: () => void;
  onOpen: () => void;
}) {
  const t = useT();
  const press = useLongPress(onStartSelecting, !selecting);
  return (
    <SwipeActions start={swipe.start} end={swipe.end} disabled={selecting}>
      <article
        className="connection-card"
        data-selecting={selecting || undefined}
        data-selected={(selecting && selected) || undefined}
        {...press}
        // While selecting, the whole card toggles; the checkbox stays the
        // control for keyboard and screen readers.
        onClick={
          selecting
            ? (event) => {
                if (!(event.target as HTMLElement).closest("[role=checkbox]"))
                  onSelectedChange(!selected);
              }
            : undefined
        }
      >
        <div className="connection-card-header">
          {selecting && (
            <Checkbox
              className="connection-card-check"
              aria-label={`${t("selectConnection")} ${row.name}`}
              checked={selected}
              onCheckedChange={(value) => onSelectedChange(value === true)}
            />
          )}
          <StatusChip tone={tone} />
          <div className="connection-card-identity">
            {selecting ? (
              <span className="connection-name bidi-name">{row.name}</span>
            ) : (
              <button
                type="button"
                className="connection-name bidi-name"
                onClick={onOpen}
              >
                {row.name}
              </button>
            )}
            <span className="flex items-center gap-1.5 text-xs text-muted-foreground">
              <EngineGlyph engine={row.engine} className="size-3.5" />
              <bdi>{engineName(row.engine)}</bdi>
            </span>
          </div>
        </div>
        <RouteChain connection={row} tone={tone} />
        {badges}
        <div className="connection-card-footer">
          <span className="connection-card-state">
            {health}
            <Status value={status} tone={tone} />
          </span>
          {!selecting && actions}
        </div>
      </article>
    </SwipeActions>
  );
}
