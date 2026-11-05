import { useContext, type ReactNode } from "react";
import {
  Check,
  Flame,
  Gauge,
  Leaf,
  ListChecks,
  Scale,
  Sparkles,
  Timer,
  Users,
  type LucideIcon,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { LocaleContext, useT } from "@/lib/i18n";
import { number } from "@/lib/format";
import { cn } from "@/lib/utils";
import { goals, levels, sameProfile } from "./catalog";
import type {
  OptimizeGoal,
  OptimizeLevel,
  OptimizeProfile,
} from "./types";

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

/** A progress ring: how much of the viewed profile this server already has. */
function Ring({ value, label }: { value: number; label: string }) {
  const locale = useContext(LocaleContext);
  const radius = 26;
  const length = 2 * Math.PI * radius;
  return (
    <div className="opt-ring" role="img" aria-label={label}>
      <svg viewBox="0 0 64 64" aria-hidden>
        <circle className="opt-ring-track" cx="32" cy="32" r={radius} />
        <circle
          className="opt-ring-value"
          cx="32"
          cy="32"
          r={radius}
          strokeDasharray={`${(length * value) / 100} ${length}`}
        />
      </svg>
      <span className="opt-ring-text">
        <bdi dir="ltr">{number(Math.round(value), locale)}%</bdi>
      </span>
    </div>
  );
}

/**
 * The intensity as one three-stop control: native radios (arrow keys move
 * between stops) drawn as a track with the chosen stop filled.
 */
function Intensity({
  value,
  onChange,
}: {
  value: OptimizeLevel;
  onChange: (level: OptimizeLevel) => void;
}) {
  const t = useT();
  const index = levels.indexOf(value);
  return (
    <fieldset className="opt-intensity" style={{ "--step": index } as React.CSSProperties}>
      <legend className="opt-field-legend">{t("optLevelLegend")}</legend>
      <div className="opt-intensity-stops">
        <div className="opt-intensity-track" aria-hidden>
          <span className="opt-intensity-fill" />
        </div>
        {levels.map((level) => {
          const Icon = levelIcons[level];
          const checked = level === value;
          return (
            <label
              key={level}
              className={cn("opt-stop", checked && "is-checked")}
              data-level={level}
            >
              <input
                type="radio"
                name="opt-level"
                value={level}
                className="sr-only"
                checked={checked}
                aria-describedby="opt-level-why"
                onChange={() => onChange(level)}
              />
              <span className="opt-stop-dot" aria-hidden>
                <Icon />
              </span>
              <span className="opt-stop-label">
                {t(`optLevel_${level}`)}
                {level === "balanced" && (
                  <span className="opt-level-tag">{t("optDefault")}</span>
                )}
              </span>
            </label>
          );
        })}
      </div>
      <p id="opt-level-why" className="opt-field-why" aria-live="polite">
        {t(`optLevelWhy_${value}`)}
      </p>
    </fieldset>
  );
}

/** What the server is mostly for, as three icon cards. */
function Goal({
  value,
  onChange,
}: {
  value: OptimizeGoal;
  onChange: (goal: OptimizeGoal) => void;
}) {
  const t = useT();
  return (
    <fieldset className="opt-goal-field">
      <legend className="opt-field-legend">{t("optGoalLegend")}</legend>
      <div className="opt-goal-cards">
        {goals.map((goal) => {
          const Icon = goalIcons[goal];
          const checked = goal === value;
          return (
            <label key={goal} className={cn("opt-goal-card", checked && "is-checked")}>
              <input
                type="radio"
                name="opt-goal"
                value={goal}
                className="sr-only"
                checked={checked}
                aria-describedby="opt-goal-why"
                onChange={() => onChange(goal)}
              />
              <span className="opt-goal-card-icon" aria-hidden>
                <Icon />
              </span>
              <span className="opt-goal-card-title">{t(`optGoal_${goal}`)}</span>
              <span className="opt-goal-card-hint">{t(`optGoalHint_${goal}`)}</span>
              {checked && <Check className="opt-goal-card-check" aria-hidden />}
            </label>
          );
        })}
      </div>
      <p id="opt-goal-why" className="opt-field-why" aria-live="polite">
        {t(`optGoalWhy_${value}`)}
      </p>
    </fieldset>
  );
}

/**
 * The Optimization summary: progress, the profile the page previews, the two
 * actions and the server facts, in one card.
 */
export function ControlCenter({
  progress,
  pending,
  allPending,
  recommendedCount,
  selected,
  saved,
  hasApplied,
  capped,
  loading,
  busy,
  onProfile,
  onApplyAll,
  onReviewRecommended,
  facts,
}: {
  /** Share of the viewed profile already in place, 0–100. */
  progress: number;
  /** Recommended changes (groups that fit this server). */
  pending: number;
  /** Changes across every group. */
  allPending: number;
  recommendedCount: number;
  selected: OptimizeProfile;
  saved: OptimizeProfile;
  hasApplied: boolean;
  capped: boolean;
  loading: boolean;
  busy: boolean;
  onProfile: (next: OptimizeProfile) => void;
  onApplyAll: () => void;
  onReviewRecommended: () => void;
  facts: ReactNode;
}) {
  const t = useT();
  const previewing = !sameProfile(selected, saved);
  const savedName = `${t(`optLevel_${saved.level}`)} · ${t(`optGoal_${saved.goal}`)}`;
  const done = allPending === 0;
  return (
    <section
      className="opt-center"
      data-state={done ? "done" : "open"}
      data-loading={loading}
      aria-labelledby="opt-center-title"
    >
      <div className="opt-center-summary">
        <Ring value={progress} label={t("optProgress").replace("{n}", String(Math.round(progress)))} />
        <div className="opt-center-text">
          <span className="opt-center-status" data-preview={previewing}>
            {previewing
              ? t("optProfilePreviewing")
              : hasApplied
                ? t("optProfileApplied").replace("{p}", savedName)
                : t("optProfileNone")}
          </span>
          <h2 id="opt-center-title" className="opt-center-title">
            {done
              ? t("optHeroNone")
              : t("optHeroTitle").replace("{n}", String(allPending))}
          </h2>
          <p className="opt-center-sub">
            {t("optHeroProfile")
              .replace("{level}", t(`optLevel_${selected.level}`))
              .replace("{goal}", t(`optGoal_${selected.goal}`))}
          </p>
        </div>
        {!done && (
          <div className="opt-center-actions">
            <Button size="lg" disabled={busy || loading} onClick={onApplyAll}>
              <ListChecks data-icon="inline-start" />
              {t("optApplyAll").replace("{n}", String(allPending))}
            </Button>
            {recommendedCount > 0 && pending < allPending && (
              <Button
                size="lg"
                variant="outline"
                disabled={busy || loading}
                onClick={onReviewRecommended}
              >
                <Sparkles data-icon="inline-start" />
                {t("optReviewRecommended")} ({pending})
              </Button>
            )}
          </div>
        )}
      </div>
      <div className="opt-center-profile">
        <Intensity
          value={selected.level}
          onChange={(level) => onProfile({ ...selected, level })}
        />
        <Goal
          value={selected.goal}
          onChange={(goal) => onProfile({ ...selected, goal })}
        />
      </div>
      {(previewing || (capped && selected.level === "aggressive")) && (
        <div className="flex flex-col gap-1.5" aria-live="polite">
          {previewing && <p className="opt-profile-note">{t("optProfilePreview")}</p>}
          {capped && selected.level === "aggressive" && (
            <p className="opt-profile-note opt-warn">{t("optProfileCapped")}</p>
          )}
        </div>
      )}
      {facts}
    </section>
  );
}
