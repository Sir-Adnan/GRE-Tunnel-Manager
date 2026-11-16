/** Mirrors control.UpdateView: the daily check and the last one-click run. */
export type UpdateRun = {
  state: "running" | "succeeded" | "failed";
  from: string;
  to?: string;
  started: string;
  finished?: string;
  error?: string;
};
export type UpdateView = {
  current: string;
  check: { current: string; latest?: string; checked: string; error?: string };
  available: boolean;
  running: boolean;
  run?: UpdateRun;
};

export const releaseNotes = (version: string) =>
  `https://github.com/Sir-Adnan/GRE-Tunnel-Manager/releases/tag/v${version}`;

/** Remembered across the restart and sign-in that an update causes. */
export type PendingUpdate = { from: string; to: string; started: number };
const key = "gtm-update";

export function rememberUpdate(value: PendingUpdate | undefined) {
  try {
    if (value) sessionStorage.setItem(key, JSON.stringify(value));
    else sessionStorage.removeItem(key);
  } catch {
    /* private mode: the result is still shown in Settings › Updates */
  }
}

export function pendingUpdate(): PendingUpdate | undefined {
  try {
    const value = JSON.parse(sessionStorage.getItem(key) || "null");
    if (
      value &&
      typeof value.from === "string" &&
      typeof value.to === "string" &&
      typeof value.started === "number"
    )
      return value;
  } catch {
    /* ignore */
  }
  return undefined;
}

/** How a started update ended, judged from what the panel reports now. */
export function updateOutcome(
  pending: PendingUpdate,
  view: UpdateView | undefined,
  now: number,
): "running" | "succeeded" | "failed" {
  if (view && view.current !== pending.from) return "succeeded";
  if (view && !view.running && view.run?.state === "failed") return "failed";
  // The version did not change, so a "succeeded" record cannot be this run.
  if (view && !view.running && view.run?.state === "succeeded") return "failed";
  // The installer gives up long before this; never wait forever.
  if (now - pending.started > 20 * 60 * 1000) return "failed";
  return "running";
}
