import { useLoaded } from "@/features/operations/hooks";
import type { NotifyEvent, NotifyView } from "./types";

/** Polled every 30 seconds while the page is visible. */
export function useNotifications() {
  return useLoaded<NotifyView>("notifications", () => 30);
}

/** Event title with its connection or plan name. */
export function eventTitle(e: NotifyEvent, t: (key: string) => string) {
  return t(`ntf_${e.kind}`).replace("{name}", e.name || e.owner || "");
}

