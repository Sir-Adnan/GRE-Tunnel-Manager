import { useState } from "react";
import { api, type HostTelemetry } from "@/lib/api";
import { usePoll } from "@/lib/use-poll";

/** Poll only this mounted, visible dashboard; never overlap requests. */
export function useHostTelemetry(enabled: boolean, interval: number) {
  const [sample, setSample] = useState<HostTelemetry>();
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
          setError(false);
        }
      } catch {
        // Hiding the page aborts a run on purpose; a timeout or failure is shown.
        if (!document.hidden) setError(true);
      }
    },
    { seconds: interval, enabled },
  );
  return { sample, error };
}
