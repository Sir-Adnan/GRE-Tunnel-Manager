import { useEffect, useState } from "react";
import { api } from "@/lib/api";
import type { Metrics } from "@/lib/api";

/** Owns drafts, API results and persisted accounting independently of presentation. */
export function useTraffic(run: (request: unknown) => Promise<void>) {
  const [metrics, setMetrics] = useState<Metrics>();
  const [enabled, setEnabled] = useState(false);
  const [interval, setInterval] = useState(60);
  const [retention, setRetention] = useState(0);
  const [ids, setIDs] = useState<string[]>([]);
  const [all, setAll] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(false);
  function accept(value: Metrics, syncDraft = false) {
    setMetrics(value);
    if (syncDraft) {
      setEnabled(value.settings.enabled);
      setInterval(value.settings.interval);
      setRetention(value.settings.retention_hours || 0);
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
  useEffect(() => {
    if (!metrics?.settings.enabled) return;
    let live = true;
    const timer = window.setInterval(
      () => {
        if (document.hidden) return;
        api<Metrics>("metrics")
          .then((value) => {
            if (live) accept(value);
          })
          .catch((e) => {
            if (live) setError(String(e));
          });
      },
      Math.max(30, metrics.settings.interval) * 1000,
    );
    return () => {
      live = false;
      window.clearInterval(timer);
    };
  }, [metrics?.settings.enabled, metrics?.settings.interval]);
  const requestedIDs = all ? [] : ids;
  const dirty = Boolean(
    metrics &&
    (enabled !== metrics.settings.enabled ||
      interval !== metrics.settings.interval ||
      retention !== (metrics.settings.retention_hours || 0) ||
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
        metrics_revision: metrics.revision,
        metrics: {
          enabled,
          interval,
          ids: requestedIDs,
          retention_hours: retention,
        },
      });
      accept(await api<Metrics>("metrics"), true);
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy(false);
    }
  }
  return {
    metrics,
    enabled,
    setEnabled,
    interval,
    setInterval,
    retention,
    setRetention,
    ids,
    setIDs,
    all,
    setAll,
    error,
    busy,
    loading,
    dirty,
    invalid,
    refresh,
    save,
  };
}
