// SVG path for a small trend line. Framework-free; unit-tested in tests/sparkline.test.mjs.

/** Samples kept per trend: about a minute at the dashboard's default 2 s cadence. */
export const sparkSamples = 30;

/** Adds a reading and keeps the newest sparkSamples; a missing reading breaks nothing, it is skipped. */
export function pushSample(history: readonly number[], value?: number | null) {
  if (value == null || !Number.isFinite(value)) return history;
  return [...history.slice(-(sparkSamples - 1)), value];
}

/**
 * Maps values onto a width × height box, oldest on the left. A fixed `max` (100 for percentages) keeps the
 * scale honest; otherwise the largest value reaches five sixths of it. Returns "" until there are two points.
 */
export function sparkPath(
  values: readonly number[],
  width: number,
  height: number,
  max?: number,
) {
  if (values.length < 2) return "";
  const top = Math.max(max ?? Math.max(...values) * 1.2, Number.EPSILON);
  const step = width / (sparkSamples - 1);
  const start = width - step * (values.length - 1);
  const pad = 1;
  return values
    .map((v, i) => {
      const x = start + step * i;
      const y =
        pad + (height - 2 * pad) * (1 - Math.min(Math.max(v, 0), top) / top);
      return `${i ? "L" : "M"}${x.toFixed(1)} ${y.toFixed(1)}`;
    })
    .join(" ");
}
