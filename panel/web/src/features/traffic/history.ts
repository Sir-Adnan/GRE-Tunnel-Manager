import type { TrafficArchive } from "@/lib/api";
export type Sample = { time: number; received: number; sent: number };

/** Plot actual selected-resource samples only; never interpolate missing epochs. */
export function archiveSamples(
  archive: TrafficArchive | undefined,
  cycleStart?: string,
  now = Date.now(),
): Sample[] {
  const start = cycleStart ? Date.parse(cycleStart) : NaN;
  const points = new Map<number, Sample>();
  for (const p of archive?.history || []) {
    const time = Date.parse(p.time);
    if (
      !Number.isFinite(time) ||
      time <= 0 ||
      time > now ||
      p.received < 0 ||
      p.sent < 0 ||
      !Number.isFinite(p.received) ||
      !Number.isFinite(p.sent)
    )
      continue;
    if (Number.isFinite(start) && start > 0 && time < start) continue;
    points.set(time, { time, received: p.received, sent: p.sent });
  }
  return [...points.values()].sort((a, b) => a.time - b.time).slice(-288);
}
