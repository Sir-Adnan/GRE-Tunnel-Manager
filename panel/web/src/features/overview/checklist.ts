import { certificateState, type AccessView } from "../settings/access.ts";

export type ChecklistInput = {
  access?: AccessView;
  security?: { two_factor: boolean };
  connections: number;
  health?: { settings: { enabled: boolean } };
  snapshots?: { settings: { enabled: boolean } };
  notify?: {
    settings: { webhook: { enabled: boolean }; telegram: { enabled: boolean } };
  };
};

export type ChecklistItem = {
  id: "https" | "twoFactor" | "connection" | "health" | "backups" | "alerts";
  done: boolean;
  page: string;
  params?: Record<string, string>;
};

/** First-run steps, each judged from what the server reports. A source that
 * has not loaded (or failed) leaves its step out rather than guessing. */
export function checklist(input: ChecklistInput, now: number): ChecklistItem[] {
  const items: (ChecklistItem | undefined)[] = [
    input.access && {
      id: "https",
      done: certificateState(input.access, now) === "valid",
      page: "settings",
      params: { tab: "security" },
    },
    input.security && {
      id: "twoFactor",
      done: input.security.two_factor,
      page: "settings",
      params: { tab: "security" },
    },
    {
      id: "connection",
      done: input.connections > 0,
      page: "connections",
      // The first connection usually links two servers: start with the wizard.
      params: { wizard: "gre" },
    },
    input.health && {
      id: "health",
      done: input.health.settings.enabled,
      page: "health",
    },
    input.snapshots && {
      id: "backups",
      done: input.snapshots.settings.enabled,
      page: "backups",
    },
    input.notify && {
      id: "alerts",
      done:
        input.notify.settings.telegram.enabled ||
        input.notify.settings.webhook.enabled,
      page: "settings",
      params: { tab: "notifications" },
    },
  ];
  return items.filter((item): item is ChecklistItem => Boolean(item));
}

const hiddenKey = "gtm-checklist-hidden";

export function checklistHidden(): boolean {
  try {
    return localStorage.getItem(hiddenKey) === "1";
  } catch {
    return false;
  }
}

export function hideChecklist(hidden: boolean) {
  try {
    if (hidden) localStorage.setItem(hiddenKey, "1");
    else localStorage.removeItem(hiddenKey);
  } catch {
    /* the card simply shows again next time */
  }
}
