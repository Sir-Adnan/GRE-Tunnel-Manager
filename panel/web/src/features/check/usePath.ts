// Polls one connection's packet path while it is shown and keeps the
// previous sample, so the view can show rates.
import { useCallback, useState } from "react";
import { api } from "@/lib/api";
import { usePoll } from "@/lib/use-poll";
import type { ConnectionPath } from "./model";
import { errorMessage } from "@/lib/i18n";

/** Seconds between samples: fast enough to watch, cheap for the broker. */
export const pathSeconds = 3;

export function usePath(id: string) {
  const [samples, setSamples] = useState<{
    prev?: ConnectionPath;
    next?: ConnectionPath;
  }>({});
  const [error, setError] = useState("");
  const load = useCallback(
    async (signal: AbortSignal) => {
      try {
        const sample = await api<ConnectionPath>(
          `connection/path?id=${encodeURIComponent(id)}`,
          undefined,
          signal,
        );
        if (signal.aborted) return;
        setSamples((s) => ({ prev: s.next, next: sample }));
        setError("");
      } catch (e) {
        if (!signal.aborted)
          setError(errorMessage(e));
      }
    },
    [id],
  );
  usePoll(load, { seconds: pathSeconds, restartOn: id, timeoutMs: 8000 });
  return { ...samples, error };
}
