import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Metrics } from "@/lib/api";
import { recordSamples } from "./history";
import type { History } from "./history";

/** Owns drafts, API results and bounded samples independently of presentation. */
export function useTraffic(run: (request: unknown) => Promise<void>) {
  const [metrics, setMetrics] = useState<Metrics>();
  const [enabled, setEnabled] = useState(false);
  const [interval, setInterval] = useState(60);
  const [ids, setIDs] = useState<string[]>([]);
  const [all, setAll] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<History>({});
  const [chartID, setChartID] = useState("");
  function accept(value: Metrics, syncDraft = false) {
    setMetrics(value);
    setHistory((current) => recordSamples(current, value));
    if (syncDraft) {
      setEnabled(value.settings.enabled);
      setInterval(value.settings.interval);
      setIDs(value.settings.ids || []);
      setAll(!value.settings.ids?.length);
    }
  }
  useEffect(() => {
    let live = true;
    api<Metrics>("metrics")
      .then((value) => {
        if (live) accept(value, true);
      })
      .catch((error) => live && setError(String(error)));
    return () => {
      live = false;
    };
  }, []);
  const requestedIDs = all ? [] : ids;
  const dirty = Boolean(
    metrics &&
    (enabled !== metrics.settings.enabled ||
      interval !== metrics.settings.interval ||
      [...requestedIDs].sort().join() !==
        [...(metrics.settings.ids || [])].sort().join()),
  );
  const invalid =
    !Number.isInteger(interval) ||
    interval < 15 ||
    interval > 3600 ||
    (enabled && !all && !ids.length);
  async function refresh() {
    setLoading(true);
    setError("");
    try {
      accept(await api<Metrics>("metrics"), !metrics);
    } catch (error) {
      setError(String(error));
    } finally {
      setLoading(false);
    }
  }
  async function save(event: React.FormEvent) {
    event.preventDefault();
    if (!metrics || invalid) return;
    setBusy(true);
    setError("");
    try {
      await run({
        action: "metrics-configure",
        metrics: { enabled, interval, ids: requestedIDs },
      });
      accept(await api<Metrics>("metrics"), true);
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy(false);
    }
  }
  const counters = Object.entries(metrics?.counters || {});
  const selectedID = counters.some(([id]) => id === chartID)
    ? chartID
    : counters[0]?.[0] || "";
  const samples = history[selectedID] || [];
  return {
    metrics,
    enabled,
    setEnabled,
    interval,
    setInterval,
    ids,
    setIDs,
    all,
    setAll,
    error,
    busy,
    loading,
    setChartID,
    dirty,
    invalid,
    refresh,
    save,
    counters,
    selectedID,
    samples,
  };
}
