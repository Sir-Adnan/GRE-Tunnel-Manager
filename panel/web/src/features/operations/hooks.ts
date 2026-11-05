import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/use-poll";
import type {
  HealthReport,
  HealthView,
  MaintenanceView,
} from "@/features/operations/types";

type Loaded<T> = {
  value?: T;
  error: string;
  reload: () => Promise<T | undefined>;
};

/**
 * Loads one read endpoint once and then polls it while the page is visible.
 * `seconds` may depend on the loaded value (pass 0 to stop polling).
 */
function useLoaded<T>(path: string, seconds: (value?: T) => number): Loaded<T> {
  const [value, setValue] = useState<T>();
  const [error, setError] = useState("");
  const reload = useCallback(
    async (signal?: AbortSignal) => {
      try {
        const next = await api<T>(path, undefined, signal);
        if (!signal?.aborted) {
          setValue(next);
          setError("");
        }
        return next;
      } catch (e) {
        if (!signal?.aborted)
          setError(e instanceof Error ? e.message : String(e));
        return undefined;
      }
    },
    [path],
  );
  // Runs at once and whenever the page becomes visible; slow refresh while idle.
  usePoll(reload, { seconds: seconds(value) || 600 });
  return { value, error, reload: () => reload() };
}

/** Polls at the monitor's own interval (at least 10 s); every 10 minutes while it is off. */
export function useHealthView() {
  return useLoaded<HealthView>("health", (v) =>
    v?.settings.enabled ? Math.max(10, v.settings.interval) : 0,
  );
}

/** Fast while a run is pending (for the countdown), otherwise every 30 s. */
export function useMaintenanceView() {
  return useLoaded<MaintenanceView>("maintenance", (v) =>
    v?.plans.some((p) => p.state.pending) ? 5 : 30,
  );
}

export function useHealthReport(week: number, weekStart: number) {
  const [value, setValue] = useState<HealthReport>();
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    api<HealthReport>(
      `health/report?week=${week}&week_start=${weekStart}`,
      undefined,
      controller.signal,
    )
      .then((next) => {
        setValue(next);
        setError("");
      })
      .catch((e) => {
        if (!controller.signal.aborted)
          setError(e instanceof Error ? e.message : String(e));
      });
    return () => controller.abort();
  }, [week, weekStart]);
  return { value, error };
}

/** Re-renders every second while mounted, for countdowns. */
export function useNow(active: boolean) {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    if (!active) return;
    const timer = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(timer);
  }, [active]);
  return now;
}
