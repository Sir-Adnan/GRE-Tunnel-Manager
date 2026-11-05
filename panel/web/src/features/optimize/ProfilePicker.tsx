import {
  Flame,
  Gauge,
  Leaf,
  Scale,
  Timer,
  Users,
  type LucideIcon,
} from "lucide-react";
import { useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import { goals, levels, sameProfile } from "./catalog";
import type { OptimizeGoal, OptimizeLevel, OptimizeProfile } from "./types";

const levelIcons: Record<OptimizeLevel, LucideIcon> = {
  conservative: Leaf,
  balanced: Scale,
  aggressive: Flame,
};
const goalIcons: Record<OptimizeGoal, LucideIcon> = {
  general: Gauge,
  users: Users,
  latency: Timer,
};

/**
 * Chooses the profile the rows below recommend: an intensity level as
 * cards and a goal as a segmented choice. Choosing previews; only Review
 * and Apply change the server.
 */
export function ProfilePicker({
  selected,
  saved,
  hasApplied,
  capped,
  loading,
  onChange,
}: {
  selected: OptimizeProfile;
  saved: OptimizeProfile;
  hasApplied: boolean;
  capped: boolean;
  loading: boolean;
  onChange: (next: OptimizeProfile) => void;
}) {
  const t = useT();
  const previewing = !sameProfile(selected, saved);
  const savedName = `${t(`optLevel_${saved.level}`)} · ${t(`optGoal_${saved.goal}`)}`;
  return (
    <section
      className="opt-profile"
      aria-labelledby="opt-profile-title"
      data-loading={loading}
    >
      <header className="opt-profile-head">
        <div className="flex min-w-0 flex-col gap-0.5">
          <h2
            id="opt-profile-title"
            className="text-base font-semibold tracking-tight"
          >
            {t("optProfileTitle")}
          </h2>
          <p className="text-sm text-muted-foreground">{t("optProfileHint")}</p>
        </div>
        <span className="opt-profile-saved" data-preview={previewing}>
          {hasApplied
            ? t("optProfileApplied").replace("{p}", savedName)
            : t("optProfileNone")}
        </span>
      </header>
      <fieldset className="opt-levels">
        <legend className="sr-only">{t("optLevelLegend")}</legend>
        {levels.map((level) => {
          const Icon = levelIcons[level];
          const checked = selected.level === level;
          return (
            <label
              key={level}
              className={cn("opt-level", checked && "is-checked")}
              data-level={level}
            >
              <input
                type="radio"
                name="opt-level"
                value={level}
                className="sr-only"
                checked={checked}
                aria-label={t(`optLevel_${level}`)}
                aria-describedby={`opt-level-${level}`}
                onChange={() => onChange({ ...selected, level })}
              />
              <span className="opt-level-icon">
                <Icon className="size-4" aria-hidden />
              </span>
              <span className="flex min-w-0 flex-col gap-0.5">
                <span className="flex flex-wrap items-center gap-1.5 text-sm font-semibold">
                  {t(`optLevel_${level}`)}
                  {level === "balanced" && (
                    <span className="opt-level-tag">{t("optDefault")}</span>
                  )}
                </span>
                <span
                  id={`opt-level-${level}`}
                  className="text-xs leading-relaxed text-muted-foreground"
                >
                  {t(`optLevelWhy_${level}`)}
                </span>
              </span>
            </label>
          );
        })}
      </fieldset>
      <fieldset className="opt-goals">
        <legend className="opt-goals-legend">{t("optGoalLegend")}</legend>
        <div className="opt-goal-options">
          {goals.map((goal) => {
            const Icon = goalIcons[goal];
            const checked = selected.goal === goal;
            return (
              <label
                key={goal}
                className={cn("opt-goal", checked && "is-checked")}
              >
                <input
                  type="radio"
                  name="opt-goal"
                  value={goal}
                  className="sr-only"
                  checked={checked}
                  aria-label={t(`optGoal_${goal}`)}
                  onChange={() => onChange({ ...selected, goal })}
                />
                <Icon className="size-3.5" aria-hidden />
                {t(`optGoal_${goal}`)}
              </label>
            );
          })}
        </div>
        <p className="text-xs leading-relaxed text-muted-foreground">
          {t(`optGoalWhy_${selected.goal}`)}
        </p>
      </fieldset>
      {(previewing || capped) && (
        <div className="flex flex-col gap-1.5" aria-live="polite">
          {previewing && (
            <p className="opt-profile-note">{t("optProfilePreview")}</p>
          )}
          {capped && selected.level === "aggressive" && (
            <p className="opt-profile-note opt-warn">{t("optProfileCapped")}</p>
          )}
        </div>
      )}
    </section>
  );
}
