import {
  Activity,
  ChevronDown,
  Network,
  RotateCcw,
  Route,
  Sparkles,
  Waypoints,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { GroupState } from "./catalog";
import { SettingRow } from "./SettingRow";
import type { OptimizeGroup } from "./types";

const icons: Record<OptimizeGroup, LucideIcon> = {
  conntrack: Network,
  queues: Activity,
  relay: Waypoints,
  routing: Route,
};

function StatusLabel({ state }: { state: GroupState }) {
  const t = useT();
  const text = {
    applied: t("optAllApplied"),
    partial: t("optPartly").replace("{n}", String(state.pending)),
    available: t("optImprovements").replace("{n}", String(state.pending)),
    current: t("optUpToDate"),
  }[state.status];
  return (
    <span className="opt-status" data-status={state.status}>
      <span className="opt-status-dot" aria-hidden />
      {text}
    </span>
  );
}

/** One group as an expandable row: summary always, settings on demand. */
export function GroupRow({
  state,
  fits,
  open,
  busy,
  toggle,
  review,
  restore,
}: {
  state: GroupState;
  fits: boolean;
  open: boolean;
  busy: boolean;
  toggle: () => void;
  review: () => void;
  restore: () => void;
}) {
  const t = useT();
  const Icon = icons[state.group];
  const panel = `opt-group-${state.group}`;
  return (
    <li className={cn("opt-row", open && "is-open")} data-status={state.status}>
      <div className="opt-row-head">
        <button
          type="button"
          className="opt-row-toggle"
          aria-expanded={open}
          aria-controls={panel}
          onClick={toggle}
        >
          <span className="opt-row-icon">
            <Icon className="size-5" />
          </span>
          <span className="opt-row-title">
            <span className="flex flex-wrap items-center gap-x-2 gap-y-1">
              <span className="text-base font-semibold tracking-tight">
                {t(`optGroup_${state.group}`)}
              </span>
              {fits && (
                <span className="opt-fit">
                  <Sparkles className="size-3" aria-hidden />
                  {t("optFitBadge")}
                </span>
              )}
            </span>
            <span className="text-sm text-muted-foreground">
              {t(`optGroupFor_${state.group}`)}
            </span>
          </span>
          <StatusLabel state={state} />
          <ChevronDown className="opt-row-chevron size-4" aria-hidden />
        </button>
        {state.pending > 0 && (
          <Button
            size="sm"
            variant={fits ? "default" : "outline"}
            className="opt-row-action"
            disabled={busy}
            onClick={review}
          >
            {t("optReview")}
          </Button>
        )}
      </div>
      {open && (
        <div id={panel} className="opt-row-body">
          <p className="opt-row-why">{t(`optGroupWhy_${state.group}`)}</p>
          {state.drifted > 0 && (
            <p className="opt-why opt-warn">
              {t("optDrifted").replace("{n}", String(state.drifted))}
            </p>
          )}
          <ul className="opt-settings">
            {state.keys.map((k) => (
              <SettingRow
                key={k.key}
                setting={k.key}
                current={k.current}
                value={k.recommended}
                note={k.note}
                reason={k.reason}
                before={k.before}
                managed={k.applied !== undefined}
                otherFile={k.other_file}
                otherValue={k.other_value}
              />
            ))}
          </ul>
          {state.applied > 0 && (
            <div className="flex justify-end">
              <Button
                variant="ghost"
                size="sm"
                disabled={busy}
                onClick={restore}
              >
                <RotateCcw data-icon="inline-start" />
                {t("optRestoreGroup")}
              </Button>
            </div>
          )}
        </div>
      )}
    </li>
  );
}
