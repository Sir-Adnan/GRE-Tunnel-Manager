import type { Metrics, TrafficPolicy } from "@/lib/api";
export function cycleUsage(c: Metrics["counters"][string]) {
  return {
    received: Math.max(0, c.received - (c.baseline_received || 0)),
    sent: Math.max(0, c.sent - (c.baseline_sent || 0)),
  };
}
export function quotaUsage(
  c: Metrics["counters"][string] | undefined,
  p: TrafficPolicy | undefined,
) {
  const v = c ? cycleUsage(c) : { received: 0, sent: 0 };
  const used =
    p?.direction === "received"
      ? v.received
      : p?.direction === "sent"
        ? v.sent
        : v.received + v.sent;
  return {
    used,
    percent: p?.limit ? Math.min(100, (100 * used) / p.limit) : 0,
    reached: Boolean(p?.limit && used >= p.limit),
  };
}
export function csvCell(v: string | number) {
  const text = String(v);
  return `"${(/^[\s]*[=+@-]/.test(text) ? "'" : "") + text.replaceAll('"', '""')}"`;
}
