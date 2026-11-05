// Framework-free notification helpers; unit-tested in tests/features.test.mjs.
import type { Locale } from "@/lib/i18n";
import type { NotifyEvent } from "./types";

/** The page an event belongs to, with optional route parameters. */
export function eventTarget(e: NotifyEvent): {
  page: string;
  params?: Record<string, string>;
} {
  switch (e.kind) {
    case "down":
    case "up":
    case "failover":
      return { page: "health" };
    case "optimize-rollback":
    case "optimize-kept":
      return { page: "optimize" };
    case "change-reverted":
      return { page: "history" };
    case "maintenance":
    case "maintenance-failed":
      return { page: "maintenance", params: { tab: "history" } };
    case "backup":
    case "backup-failed":
      return { page: "backups", params: { tab: "schedule" } };
  }
  return { page: "settings" };
}

const intl = (locale: Locale) => (locale === "fa" ? "fa-IR-u-nu-latn" : "en");

/** "3 min ago", "یک ساعت پیش"; Latin digits in both locales. */
export function relative(value: string, now: number, locale: Locale): string {
  const seconds = Math.round((Date.parse(value) - now) / 1000);
  if (Number.isNaN(seconds)) return "—";
  const format = new Intl.RelativeTimeFormat(intl(locale), { numeric: "auto" });
  const abs = Math.abs(seconds);
  if (abs < 45) return format.format(0, "second");
  if (abs < 3600) return format.format(Math.round(seconds / 60), "minute");
  if (abs < 86400) return format.format(Math.round(seconds / 3600), "hour");
  return format.format(Math.round(seconds / 86400), "day");
}

/** Calendar day key in the viewer's zone, for grouping. */
export function dayKey(value: string): string {
  const d = new Date(value);
  return `${d.getFullYear()}-${d.getMonth()}-${d.getDate()}`;
}

/** Groups newest-first items by calendar day, keeping order. */
export function byDay<T extends { time: string }>(
  events: T[],
): { day: string; events: T[] }[] {
  const out: { day: string; events: T[] }[] = [];
  for (const e of events) {
    const day = dayKey(e.time);
    const last = out[out.length - 1];
    if (last?.day === day) last.events.push(e);
    else out.push({ day, events: [e] });
  }
  return out;
}

/** "Today", "Yesterday" or a short date. */
export function dayLabel(
  value: string,
  now: number,
  locale: Locale,
  t: (key: string) => string,
): string {
  const key = dayKey(value);
  if (key === dayKey(new Date(now).toISOString())) return t("ntfToday");
  if (key === dayKey(new Date(now - 86400000).toISOString()))
    return t("ntfYesterday");
  return new Date(value).toLocaleDateString(intl(locale), {
    month: "short",
    day: "numeric",
    weekday: "short",
  });
}

/** Badge text: 1–99 or 99+. */
export function unreadBadge(n: number): string {
  return n > 99 ? "99+" : String(n);
}

/** A localized detail from the event's arguments; the raw detail otherwise. */
export function eventDetail(
  e: NotifyEvent,
  t: (key: string) => string,
  locale: Locale,
): string {
  const a = e.args ?? {};
  switch (e.kind) {
    case "up":
      if (a.seconds) return t("ntfDetail_up").replace("{d}", durationText(Number(a.seconds), locale));
      break;
    case "down":
      if (a.endpoint)
        return a.reason
          ? `${a.endpoint} · ${t(`reason_${a.reason}`).replace(/^reason_/, "")}`
          : a.endpoint;
      break;
    case "failover":
      if ("excluded" in a)
        return a.excluded
          ? t("ntfDetail_failoverOn").replace("{list}", a.excluded)
          : t("ntfDetail_failoverOff");
      break;
    case "optimize-kept":
      if (a.minutes) return t("ntfDetail_kept").replace("{n}", a.minutes);
      break;
    case "optimize-rollback":
      if (a.names && !a.error) return t("ntfDetail_rollback").replace("{names}", a.names);
      break;
    case "change-reverted":
      if (a.skipped) return t("ntfDetail_revertSkipped");
      if (a.reason && !a.error) return t(a.reason === "timeout" ? "ntfDetail_revertTimeout" : "ntfDetail_revertManual");
      break;
    case "backup":
      if (a.name) return t("ntfDetail_backup").replace("{name}", a.name).replace("{c}", a.connections ?? "0");
      break;
    case "maintenance":
    case "maintenance-failed":
      if (a.count && !e.detail)
        return t("ntfDetail_maintenance")
          .replace("{action}", t(`action_${a.action}`))
          .replace("{n}", a.count);
  }
  return e.detail ?? "";
}

function durationText(seconds: number, locale: Locale): string {
  const units = locale === "fa" ? [" روز", " ساعت", " دقیقه"] : ["d", "h", "m"];
  const parts: string[] = [];
  let rest = Math.max(0, Math.round(seconds));
  [86400, 3600, 60].forEach((size, i) => {
    const n = Math.floor(rest / size);
    if (n > 0 && parts.length < 2) {
      parts.push(`${n}${units[i]}`);
      rest %= size;
    }
  });
  return parts.length ? parts.join(" ") : `${rest}${locale === "fa" ? " ثانیه" : "s"}`;
}
