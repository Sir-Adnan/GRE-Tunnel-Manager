// Runs the guided check for one owner when it mounts; run() repeats it.
import { useCallback, useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { DiagnoseReport } from "./order";
import { errorMessage } from "@/lib/i18n";

export function useDiagnosis(owner?: string) {
  const [report, setReport] = useState<DiagnoseReport>();
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(Boolean(owner));
  const load = useCallback(
    async (signal?: AbortSignal) => {
      if (!owner) return;
      try {
        const next = await api<DiagnoseReport>(
          `diagnose?owner=${encodeURIComponent(owner)}`,
          undefined,
          signal,
        );
        if (signal?.aborted) return;
        setReport(next);
        setError("");
      } catch (e) {
        if (!signal?.aborted)
          setError(errorMessage(e));
      } finally {
        if (!signal?.aborted) setBusy(false);
      }
    },
    [owner],
  );
  // Callers remount per owner (key), so state starts empty. Like the
  // original dialog, the first run resolves outside the effect body.
  useEffect(() => {
    if (!owner) return;
    const controller = new AbortController();
    const url = `diagnose?owner=${encodeURIComponent(owner)}`;
    api<DiagnoseReport>(url, undefined, controller.signal)
      .then(setReport)
      .catch((e) => {
        if (!controller.signal.aborted)
          setError(errorMessage(e));
      })
      .finally(() => {
        if (!controller.signal.aborted) setBusy(false);
      });
    return () => controller.abort();
  }, [owner]);
  const run = () => {
    setBusy(true);
    setError("");
    void load();
  };
  return { report, error, busy, run };
}
