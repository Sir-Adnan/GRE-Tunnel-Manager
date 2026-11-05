import { useContext } from "react";
import { LocaleContext, useT } from "@/lib/i18n";
import { cn } from "@/lib/utils";
import type { HealthPoint, HealthStatus } from "@/features/operations/types";
import { percent, uptimeTone } from "./format";

const statusKey: Record<HealthStatus, string> = {
  up: "healthUp",
  degraded: "healthDegraded",
  down: "healthDown",
  unknown: "healthUnknown",
};

/** Color is never the only signal: every pill carries its text label. */
export function StatusPill({
  status,
  className,
}: {
  status: HealthStatus;
  className?: string;
}) {
  const t = useT();
  return (
    <span className={cn("status-pill", className)} data-status={status}>
      <span className="status-pill-dot" aria-hidden />
      {t(statusKey[status])}
    </span>
  );
}

/**
 * One cell per hour or day, oldest first. Each cell is a labelled image for
 * screen readers; the strip itself reads as a list.
 */
export function UptimeBars({
  cells,
  label,
  cellLabel,
  className,
}: {
  cells: (number | null)[];
  label: string;
  cellLabel: (index: number) => string;
  className?: string;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  return (
    <ol className={cn("uptime-bars", className)} aria-label={label} dir="ltr">
      {cells.map((value, index) => {
        const text = t("healthHourCell")
          .replace("{t}", cellLabel(index))
          .replace(
            "{v}",
            value == null ? t("healthNoData") : percent(value, locale),
          );
        return (
          <li
            key={index}
            className="uptime-cell"
            data-tone={uptimeTone(value)}
            title={text}
            aria-label={text}
          />
        );
      })}
    </ol>
  );
}

/** Recent RTTs as a line; failed checks are marked at the baseline. */
export function Sparkline({
  points,
  label,
  className,
}: {
  points: HealthPoint[];
  label: string;
  className?: string;
}) {
  const width = 120,
    height = 28;
  const recent = points.slice(-60);
  const values = recent.filter((p) => p.r >= 0).map((p) => p.r);
  if (recent.length < 2 || !values.length)
    return <span className={cn("sparkline is-empty", className)} aria-hidden />;
  const max = Math.max(...values) * 1.15 || 1;
  const step = width / Math.max(1, recent.length - 1);
  const y = (r: number) => height - 2 - (Math.max(0, r) / max) * (height - 4);
  let path = "";
  recent.forEach((p, i) => {
    if (p.r < 0) return;
    const previous = recent[i - 1];
    path += `${!previous || previous.r < 0 ? "M" : "L"}${(i * step).toFixed(1)},${y(p.r).toFixed(1)}`;
  });
  return (
    <svg
      className={cn("sparkline", className)}
      viewBox={`0 0 ${width} ${height}`}
      preserveAspectRatio="none"
      role="img"
      aria-label={label}
    >
      <path
        d={path}
        className="sparkline-line"
        vectorEffect="non-scaling-stroke"
      />
      {recent.map((p, i) =>
        p.r < 0 ? (
          <rect
            key={i}
            className="sparkline-fail"
            x={i * step - 1}
            y={height - 6}
            width={2}
            height={6}
          />
        ) : null,
      )}
    </svg>
  );
}

/** A labelled horizontal meter for percentages. */
export function Meter({
  value,
  label,
  warn = 70,
  danger = 90,
}: {
  value?: number;
  label: string;
  warn?: number;
  danger?: number;
}) {
  const tone =
    value == null
      ? "none"
      : value >= danger
        ? "bad"
        : value >= warn
          ? "warn"
          : "ok";
  return (
    <div
      className="meter"
      data-tone={tone}
      role="meter"
      aria-label={label}
      aria-valuemin={0}
      aria-valuemax={100}
      aria-valuenow={value == null ? undefined : Math.round(value)}
    >
      <div style={{ width: `${Math.max(0, Math.min(100, value ?? 0))}%` }} />
    </div>
  );
}
