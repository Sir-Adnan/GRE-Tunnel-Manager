import { useEffect, useRef } from "react";

export type PollOptions = {
  /** Seconds between runs; the timer is restarted only when this changes. */
  seconds: number;
  enabled?: boolean;
  /** Run once on start and whenever the page becomes visible again (default true). */
  immediate?: boolean;
  /** Abort a run that takes longer than this (default 12 s). */
  timeoutMs?: number;
  /** Restart (and run at once) when this value changes, e.g. the id of the record being polled. */
  restartOn?: unknown;
};

/**
 * Shared polling contract for the panel: runs only while the page is visible, never overlaps runs, aborts the
 * run in flight when the page is hidden or the component unmounts, and always calls the latest `task`
 * without restarting the timer. The task reports its own errors; a rejected run is otherwise ignored.
 */
export function usePoll(
  task: (signal: AbortSignal) => Promise<unknown>,
  {
    seconds,
    enabled = true,
    immediate = true,
    timeoutMs = 12000,
    restartOn,
  }: PollOptions,
) {
  const latest = useRef(task);
  useEffect(() => {
    latest.current = task;
  });
  useEffect(() => {
    if (!enabled || !(seconds > 0)) return;
    let disposed = false,
      running = false;
    let request: AbortController | undefined;
    async function run() {
      if (document.hidden || running || disposed) return;
      running = true;
      request = new AbortController();
      const timeout = window.setTimeout(() => request?.abort(), timeoutMs);
      try {
        await latest.current(request.signal);
      } catch {
        /* reported by the task */
      } finally {
        window.clearTimeout(timeout);
        running = false;
      }
    }
    const visible = () => {
      if (document.hidden) request?.abort();
      else if (immediate) void run();
    };
    if (immediate) void run();
    const timer = window.setInterval(() => void run(), seconds * 1000);
    document.addEventListener("visibilitychange", visible);
    return () => {
      disposed = true;
      request?.abort();
      window.clearInterval(timer);
      document.removeEventListener("visibilitychange", visible);
    };
  }, [enabled, seconds, immediate, timeoutMs, restartOn]);
}
