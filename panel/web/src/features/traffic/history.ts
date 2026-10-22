import type { Metrics } from "@/lib/api";
export type Sample = { time: number; received: number; sent: number };
export type History = Record<string, Sample[]>;

/** Bounded session samples; never invent a starting point or combine overlapping resources. */
export function recordSamples(history: History, metrics: Metrics): History {
  const next = { ...history };
  for (const [id, counter] of Object.entries(metrics.counters)) {
    const time = Date.parse(counter.updated);
    if (!Number.isFinite(time) || time <= 0) continue;
    const previous = next[id] || [];
    if (previous.length && previous[previous.length - 1].time >= time) continue;
    next[id] = [
      ...previous,
      { time, received: counter.received, sent: counter.sent },
    ].slice(-60);
  }
  for (const id of Object.keys(next))
    if (!(id in metrics.counters)) delete next[id];
  return next;
}
