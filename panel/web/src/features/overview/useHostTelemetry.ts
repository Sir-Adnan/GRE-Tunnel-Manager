import { useEffect, useState } from "react";
import { api, type HostTelemetry } from "@/lib/api";

/** Poll only this mounted, visible dashboard; never overlap requests. */
export function useHostTelemetry(enabled: boolean, interval: number) {
  const [sample, setSample] = useState<HostTelemetry>();
  const [error, setError] = useState(false);
  useEffect(() => {
    if (!enabled) return;
    let disposed = false,
      running = false;
    let request: AbortController | undefined;
    async function refresh() {
      if (document.hidden || running || disposed) return;
      running = true;
      request = new AbortController();
      const timeout = window.setTimeout(() => request?.abort(), 12000);
      try {
        const value = await api<HostTelemetry>(
          "host/telemetry",
          undefined,
          request.signal,
        );
        if (!disposed) {
          setSample(value);
          setError(false);
        }
      } catch {
        if (!disposed) setError(true);
      } finally {
        window.clearTimeout(timeout);
        running = false;
      }
    }
    const visible = () => {
      if (document.hidden) request?.abort();
      else void refresh();
    };
    void refresh();
    const timer = window.setInterval(() => void refresh(), interval * 1000);
    document.addEventListener("visibilitychange", visible);
    return () => {
      disposed = true;
      request?.abort();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [enabled, interval]);
  return { sample, error };
}
