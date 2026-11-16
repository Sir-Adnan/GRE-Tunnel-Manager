// Latency history of one monitored connection: types and chart rows.
// Framework-free; unit-tested in tests/latency.test.mjs.

export const latencyRanges = ["1h", "24h", "7d", "30d"] as const;
export type LatencyRange = (typeof latencyRanges)[number];

export type LatencyPoint = {
  t: string;
  checks: number;
  mean_ms: number | null;
  max_ms: number | null;
  jitter_ms: number | null;
  /** Percentage of failed checks. */
  loss: number | null;
};

export type LatencyHistory = {
  owner: string;
  name: string;
  range: LatencyRange;
  step_seconds: number;
  points: LatencyPoint[];
  summary: LatencyPoint;
};

export type LatencyRow = {
  time: number;
  mean: number | null;
  max: number | null;
  /** The spread from the average up to the peak, drawn as a band. */
  band: [number, number] | null;
  /** Loss bars only where something was lost, so a clean range draws none. */
  loss: number | null;
};

/** Chart rows; steps without checks stay gaps instead of dropping to zero. */
export function latencyRows(history: LatencyHistory): LatencyRow[] {
  return history.points.map((p) => ({
    time: Date.parse(p.t),
    mean: p.mean_ms,
    max: p.max_ms,
    band:
      p.mean_ms === null || p.max_ms === null ? null : [p.mean_ms, p.max_ms],
    loss: p.loss ? p.loss : null,
  }));
}

/** The API path of one owner's history. */
export function latencyPath(owner: string, range: LatencyRange): string {
  return `health/latency?owner=${encodeURIComponent(owner)}&range=${range}`;
}

/** How often to refresh: the last hour moves every minute, longer ranges slowly. */
export function latencyRefresh(range: LatencyRange): number {
  return range === "1h" ? 60 : range === "24h" ? 300 : 1800;
}

/** Axis labels: clock time for short ranges, day and month for long ones. */
export function latencyTick(
  value: number,
  range: LatencyRange,
  locale: "en" | "fa",
  timeZone?: string,
): string {
  const options: Intl.DateTimeFormatOptions =
    range === "1h" || range === "24h"
      ? { hour: "2-digit", minute: "2-digit", hour12: false }
      : { month: "short", day: "numeric" };
  const language = locale === "fa" ? "fa-IR-u-nu-latn" : "en-GB";
  try {
    return new Date(value).toLocaleString(language, { ...options, timeZone });
  } catch {
    return new Date(value).toLocaleString(language, options);
  }
}
