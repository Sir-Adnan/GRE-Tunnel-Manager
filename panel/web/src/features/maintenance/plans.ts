// Plan defaults, templates, validation and human-readable summaries. Framework-free
// (type-only imports) so Node unit tests cover it; mirrors panel/internal/maintenance.
import type {
  Action,
  Owner,
  Plan,
  TriggerKind,
} from "@/features/operations/types";

export const actions: Action[] = ["refresh", "restart", "reboot"];
export const triggerKinds: TriggerKind[] = [
  "daily",
  "interval",
  "weekly",
  "uptime",
  "health",
];

/** Mirrors maintenance.Applies: refresh only where a non-disruptive path exists. */
export function applies(action: Action, engine: string) {
  if (action === "refresh")
    return ["nftables", "iptables", "haproxy"].includes(engine);
  if (action === "restart")
    return [
      "nftables",
      "iptables",
      "haproxy",
      "realm",
      "gre",
      "frp",
      "rathole",
    ].includes(engine);
  return false;
}

export function newPlan(): Plan {
  return {
    id: "",
    name: "",
    enabled: true,
    action: "restart",
    scope: [],
    trigger: { kind: "daily", times: ["04:30"] },
    guards: { cooldown: 60, max_per_day: 1, stagger: 5 },
    dry_run: false,
  };
}

export type TemplateID =
  | "nightlyRefresh"
  | "nightlyReset"
  | "healServices"
  | "healLatency"
  | "weeklyReboot"
  | "uptimeReboot";

/** Starting points that encode the safe defaults described in docs/OPERATIONS.md. */
export const templates: { id: TemplateID; action: Action; plan: () => Plan }[] =
  [
    {
      id: "nightlyRefresh",
      action: "refresh",
      plan: () => ({
        ...newPlan(),
        action: "refresh",
        trigger: { kind: "daily", times: ["04:30"] },
        guards: { cooldown: 60, max_per_day: 1, stagger: 2 },
      }),
    },
    {
      id: "nightlyReset",
      action: "restart",
      plan: () => ({
        ...newPlan(),
        trigger: { kind: "daily", times: ["04:30"] },
        guards: {
          quiet_mbps: 20,
          quiet_wait: 90,
          quiet_timeout: "skip",
          cooldown: 360,
          max_per_day: 1,
          stagger: 10,
        },
      }),
    },
    {
      id: "healServices",
      action: "restart",
      plan: () => ({
        ...newPlan(),
        trigger: { kind: "health", condition: "down", minutes: 3 },
        guards: { cooldown: 30, max_per_day: 6, stagger: 5 },
      }),
    },
    {
      id: "healLatency",
      action: "restart",
      plan: () => ({
        ...newPlan(),
        trigger: {
          kind: "health",
          condition: "latency",
          minutes: 10,
          latency_ms: 400,
        },
        guards: {
          window: "02:00-07:00",
          cooldown: 240,
          max_per_day: 2,
          stagger: 10,
        },
      }),
    },
    {
      id: "weeklyReboot",
      action: "reboot",
      plan: () => ({
        ...newPlan(),
        action: "reboot",
        trigger: { kind: "weekly", days: [5], times: ["04:30"] },
        guards: { cooldown: 1440, max_per_day: 1, min_uptime: 30, notice: 5 },
      }),
    },
    {
      id: "uptimeReboot",
      action: "reboot",
      plan: () => ({
        ...newPlan(),
        action: "reboot",
        trigger: { kind: "uptime", uptime_days: 7, times: ["04:30"] },
        guards: {
          quiet_mbps: 20,
          quiet_wait: 120,
          quiet_timeout: "skip",
          cooldown: 1440,
          max_per_day: 1,
          min_uptime: 30,
          notice: 5,
        },
      }),
    },
  ];

const clock = /^([01]\d|2[0-3]):[0-5]\d$/;

/** Returns a message key for the first invalid field, or "" when the plan is valid. */
export function validatePlan(plan: Plan): string {
  const t = plan.trigger,
    g = plan.guards;
  const times = t.times ?? [];
  const timesValid =
    times.length >= 1 && times.length <= 6 && times.every((v) => clock.test(v));
  const int = (v: number | undefined, a: number, b: number) =>
    v !== undefined && Number.isInteger(v) && v >= a && v <= b;
  if (!plan.name.trim() || plan.name.trim().length > 60)
    return "planNameInvalid";
  if (t.kind === "interval" && !int(t.hours, 1, 168)) return "planHoursInvalid";
  if (
    (t.kind === "daily" || t.kind === "weekly" || t.kind === "uptime") &&
    !timesValid
  )
    return "planTimesInvalid";
  if (t.kind === "weekly" && !(t.days && t.days.length))
    return "planDaysInvalid";
  if (
    t.kind === "uptime" &&
    (plan.action !== "reboot" || !int(t.uptime_days, 1, 60))
  )
    return "planUptimeInvalid";
  if (t.kind === "health") {
    if (!int(t.minutes, 1, 120)) return "planMinutesInvalid";
    if (t.condition === "latency" && !int(t.latency_ms, 20, 5000))
      return "planLatencyInvalid";
  }
  if (plan.action === "reboot" && t.kind !== "health" && plan.scope.length)
    return "planRebootScope";
  if (g.window) {
    const [a, b] = g.window.split("-");
    if (!clock.test(a ?? "") || !clock.test(b ?? "") || a === b)
      return "planWindowInvalid";
  }
  if (!int(g.max_per_day, 1, 48)) return "planMaxInvalid";
  if (!int(g.cooldown, 0, 10080)) return "planCooldownInvalid";
  if (g.notice !== undefined && !int(g.notice, 0, 60))
    return "planNoticeInvalid";
  if (g.stagger !== undefined && !int(g.stagger, 0, 300))
    return "planStaggerInvalid";
  if (g.min_uptime !== undefined && !int(g.min_uptime, 0, 1440))
    return "planMinUptimeInvalid";
  if (g.quiet_mbps && (g.quiet_mbps < 0 || !int(g.quiet_wait ?? 0, 0, 360)))
    return "planQuietInvalid";
  return "";
}

/** Normalizes a draft into the wire shape: only the active trigger's fields are kept. */
export function cleanPlan(plan: Plan): Plan {
  const t = plan.trigger;
  const trigger: Plan["trigger"] = { kind: t.kind };
  if (t.kind === "interval") trigger.hours = t.hours;
  if (t.kind === "daily" || t.kind === "weekly" || t.kind === "uptime")
    trigger.times = [...new Set(t.times ?? [])].sort();
  if (t.kind === "weekly") trigger.days = [...new Set(t.days ?? [])].sort();
  if (t.kind === "uptime") trigger.uptime_days = t.uptime_days;
  if (t.kind === "health") {
    trigger.condition = t.condition ?? "down";
    trigger.minutes = t.minutes;
    if (trigger.condition === "latency") trigger.latency_ms = t.latency_ms;
  }
  const g = { ...plan.guards };
  if (!g.quiet_mbps) {
    delete g.quiet_mbps;
    delete g.quiet_wait;
    delete g.quiet_timeout;
  } else g.quiet_timeout ||= "skip";
  if (!g.window) delete g.window;
  if (plan.action !== "reboot") delete g.min_uptime;
  const scope =
    plan.action === "reboot" && t.kind !== "health" ? [] : [...plan.scope];
  return { ...plan, name: plan.name.trim(), trigger, guards: g, scope };
}

/** Week order for day pickers: Saturday first in Persian, Monday first in English. */
export function weekOrder(locale: "fa" | "en") {
  return locale === "fa" ? [6, 0, 1, 2, 3, 4, 5] : [1, 2, 3, 4, 5, 6, 0];
}

export function scopedOwners(plan: Plan, owners: Owner[]) {
  const watched = owners.filter(
    (o) => plan.action === "reboot" || applies(plan.action, o.engine),
  );
  return plan.scope.length
    ? watched.filter((o) => plan.scope.includes(o.id))
    : watched;
}

/** A short sentence for the trigger, built from message keys. */
export function triggerSummary(
  plan: Plan,
  t: (key: string) => string,
  dayName: (day: number) => string,
) {
  const trigger = plan.trigger;
  const times = (trigger.times ?? []).join(", ");
  switch (trigger.kind) {
    case "interval":
      return t("summaryInterval").replace("{n}", String(trigger.hours ?? 0));
    case "daily":
      return t("summaryDaily").replace("{times}", times);
    case "weekly":
      return t("summaryWeekly")
        .replace("{days}", (trigger.days ?? []).map(dayName).join(", "))
        .replace("{times}", times);
    case "uptime":
      return t("summaryUptime")
        .replace("{n}", String(trigger.uptime_days ?? 0))
        .replace("{times}", times);
    case "health":
      return (
        trigger.condition === "latency"
          ? t("summaryLatency").replace("{ms}", String(trigger.latency_ms ?? 0))
          : t("summaryDown")
      ).replace("{n}", String(trigger.minutes ?? 0));
  }
}
