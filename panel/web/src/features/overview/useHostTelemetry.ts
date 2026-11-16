import { useState } from "react";
import { api, type HostTelemetry } from "@/lib/api";
import { pushSample } from "@/lib/sparkline";
import { usePoll } from "@/lib/use-poll";

/** Recent readings for the trend lines, newest last. Kept in memory only, for this page view. */
export type TelemetryTrends = {
  cpu: readonly number[];
  memory: readonly number[];
  received: readonly number[];
  sent: readonly number[];
};
const noTrends: TelemetryTrends = {
  cpu: [],
  memory: [],
  received: [],
  sent: [],
};

function addTrends(t: TelemetryTrends, s: HostTelemetry): TelemetryTrends {
  const memory = s.memory_total
    ? (100 * (s.memory_total - s.memory_available)) / s.memory_total
    : null;
  return {
    cpu: pushSample(t.cpu, s.cpu_percent),
    memory: pushSample(t.memory, memory),
    received: pushSample(t.received, s.received_per_second),
    sent: pushSample(t.sent, s.sent_per_second),
  };
}

/** Poll only this mounted, visible dashboard; never overlap requests. */
export function useHostTelemetry(enabled: boolean, interval: number) {
  const [sample, setSample] = useState<HostTelemetry>();
  const [trends, setTrends] = useState(noTrends);
  const [error, setError] = useState(false);
  usePoll(
    async (signal) => {
      try {
        const value = await api<HostTelemetry>(
          "host/telemetry",
          undefined,
          signal,
        );
        if (!signal.aborted) {
          setSample(value);
          setTrends((t) => addTrends(t, value));
          setError(false);
        }
      } catch {
        // Hiding the page aborts a run on purpose; a timeout or failure is shown.
        if (!document.hidden) setError(true);
      }
    },
    { seconds: interval, enabled },
  );
  return { sample, trends, error };
}
