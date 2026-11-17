// One connection as a card (phones and narrow panes). Quiet by default: the
// status, the route, its live speed and the everyday actions. The toolbar's
// "Select" turns every card into a selectable one. A long press is left to
// the browser, so addresses and names can be selected and copied; reordering
// has its own list (components/ReorderList), so no card carries a drag handle.
import type { ReactNode } from "react";
import { Checkbox } from "@/components/ui/checkbox";
import { EngineGlyph, Status } from "@/components/shared";
import { SwipeActions, type SwipeAction } from "@/components/SwipeActions";
import { LiveRateBadge } from "@/features/traffic/live";
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
  onOpen: () => void;
}) {
  const t = useT();
  return (
    <SwipeActions start={swipe.start} end={swipe.end} disabled={selecting}>
      <article
        className="connection-card"
        data-selecting={selecting || undefined}
        data-selected={(selecting && selected) || undefined}
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
          <LiveRateBadge id={row.id} className="is-stacked" />
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
