// Live per-connection throughput. One poll per page (the provider), every
// 2 seconds while the page is visible; the server reads the counters usage
// collection already keeps, so nothing runs when no one is looking. Trends
// live in memory for this page view only.
import { createContext, useContext, useMemo, useState } from "react";
import { api, type TrafficLive } from "@/lib/api";
import { pushSample } from "@/lib/sparkline";
import { usePoll } from "@/lib/use-poll";

export type LiveRate = { received: number; sent: number };
export type LiveTraffic = {
  /** Usage collection is on, so rates can exist. Undefined until the first answer. */
  enabled?: boolean;
  /** A second sample has arrived, so rates are real. */
  ready: boolean;
  error: boolean;
  rates: Record<string, LiveRate>;
  /** Combined rate of every collected connection, newest last. */
  total: { received: readonly number[]; sent: readonly number[] };
  /** Received + sent per connection, newest last. */
  trends: Record<string, readonly number[]>;
};

const idle: LiveTraffic = {
  ready: false,
  error: false,
  rates: {},
  total: { received: [], sent: [] },
  trends: {},
};

const none: ReadonlySet<string> = new Set();

export const LiveContext = createContext<LiveTraffic>(idle);

/** `uncounted`: ids left out of the total (GRE interfaces carry the same bytes as the forwards over them). */
function accept(
  current: LiveTraffic,
  sample: TrafficLive,
  uncounted: ReadonlySet<string>,
): LiveTraffic {
  if (!sample.enabled) return { ...idle, enabled: false };
  const rates: Record<string, LiveRate> = {};
  let received = 0,
    sent = 0;
  for (const [id, r] of Object.entries(sample.rates)) {
    rates[id] = { received: r.received_per_second, sent: r.sent_per_second };
    if (uncounted.has(id)) continue;
    received += r.received_per_second;
    sent += r.sent_per_second;
  }
  const ready = sample.window_seconds > 0;
  if (!ready) return { ...current, enabled: true, ready, error: false, rates };
  const trends: Record<string, readonly number[]> = {};
  for (const [id, r] of Object.entries(rates))
    trends[id] = pushSample(current.trends[id] ?? [], r.received + r.sent);
  return {
    enabled: true,
    ready,
    error: Boolean(sample.error),
    rates,
    trends,
    total: {
      received: pushSample(current.total.received, received),
      sent: pushSample(current.total.sent, sent),
    },
  };
}

/** Polls metrics/live; slows to 30 s while usage collection is off. */
export function useLiveTraffic(
  enabled = true,
  uncounted: ReadonlySet<string> = none,
): LiveTraffic {
  const [state, setState] = useState<LiveTraffic>(idle);
  usePoll(
    async (signal) => {
      try {
        const sample = await api<TrafficLive>(
          "metrics/live",
          undefined,
          signal,
        );
        if (!signal.aborted) setState((s) => accept(s, sample, uncounted));
      } catch {
        if (!signal.aborted && !document.hidden)
          setState((s) => ({ ...s, error: true }));
      }
    },
    { seconds: state.enabled === false ? 30 : 2, enabled },
  );
  return state;
}

export const useLive = () => useContext(LiveContext);

/** The busiest connections right now, highest combined rate first. */
export function useBusiest(limit: number) {
  const { rates } = useLive();
  return useMemo(
    () =>
      Object.entries(rates)
        .map(([id, r]) => ({ id, ...r, total: r.received + r.sent }))
        .filter((r) => r.total > 0)
        .sort((a, b) => b.total - a.total)
        .slice(0, limit),
    [rates, limit],
  );
}
