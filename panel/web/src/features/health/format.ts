// Framework-free formatting for health views; unit-tested in tests/operations.test.mjs.
// Runtime imports stay out of this module so Node can test it without the bundler.
import type { Locale } from "@/lib/i18n";
import type { HealthReport } from "@/features/operations/types";

function number(value: number, locale: Locale, digits = 0) {
  return new Intl.NumberFormat(locale === "fa" ? "fa-IR-u-nu-latn" : "en-US", {
    maximumFractionDigits: digits,
  }).format(value);
}

/** Same contract as the traffic CSV: quoted, with spreadsheet formulas neutralized. */
function csvCell(value: string | number) {
  const text = String(value);
  return `"${(/^[\s]*[=+@-]/.test(text) ? "'" : "") + text.replaceAll('"', '""')}"`;
}

const units = {
  en: { d: "d", h: "h", m: "m", s: "s" },
  fa: { d: "روز", h: "ساعت", m: "دقیقه", s: "ثانیه" },
} as const;

/** Two largest non-zero units, e.g. "2h 15m" or "2 ساعت 15 دقیقه". */
export function duration(seconds: number, locale: Locale): string {
  const total = Math.max(0, Math.round(seconds));
  const parts: [number, keyof (typeof units)["en"]][] = [
    [Math.floor(total / 86400), "d"],
    [Math.floor((total % 86400) / 3600), "h"],
    [Math.floor((total % 3600) / 60), "m"],
    [total % 60, "s"],
  ];
  const shown = parts.filter(([value]) => value > 0).slice(0, 2);
  const label = units[locale];
  const join = locale === "fa" ? " " : "";
  return (shown.length ? shown : [[0, "s"] as [number, "s"]])
    .map(([value, unit]) => `${number(value, locale)}${join}${label[unit]}`)
    .join(" ");
}

export type Tone = "ok" | "warn" | "bad" | "none";

/** Status-page thresholds: 99.5 % and above is healthy, below 97 % needs attention. */
export function uptimeTone(value: number | null | undefined): Tone {
  if (value == null) return "none";
  if (value >= 99.5) return "ok";
  return value >= 97 ? "warn" : "bad";
}

export function percent(value: number | null | undefined, locale: Locale) {
  return value == null ? "—" : `${number(value, locale, 2)}%`;
}

export function milliseconds(value: number | null | undefined, locale: Locale) {
  return value == null
    ? "—"
    : `${number(value, locale, value < 10 ? 1 : 0)} ms`;
}

/** Local date/time with Latin digits in both locales. */
export function stamp(
  value: string | number | undefined,
  locale: Locale,
  timeZone?: string,
  withDate = true,
) {
  if (value === undefined || value === "") return "—";
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return "—";
  const options: Intl.DateTimeFormatOptions = {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
    ...(withDate ? { month: "short", day: "numeric" } : {}),
  };
  try {
    return date.toLocaleString(locale === "fa" ? "fa-IR-u-nu-latn" : "en-GB", {
      ...options,
      timeZone,
    });
  } catch {
    return date.toLocaleString(
      locale === "fa" ? "fa-IR-u-nu-latn" : "en-GB",
      options,
    );
  }
}

/** Seconds from now (negative: in the past). */
export function secondsUntil(value: string | undefined, now = Date.now()) {
  if (!value) return undefined;
  const time = new Date(value).getTime();
  return Number.isNaN(time) ? undefined : (time - now) / 1000;
}

/** Spreadsheet export of a weekly report; formulas are neutralized. */
export function reportCSV(report: HealthReport, headers: string[]): string {
  const rows = report.rows.map((row) => {
    const traffic = report.traffic[row.owner];
    return [
      row.name,
      row.owner,
      row.engine,
      row.uptime ?? "",
      row.outages,
      Math.round(row.downtime_seconds),
      row.latency_ms ?? "",
      row.latency_max_ms ?? "",
      row.jitter_ms ?? "",
      traffic?.received ?? "",
      traffic?.sent ?? "",
    ];
  });
  return [headers, ...rows]
    .map((row) => row.map((cell) => csvCell(cell)).join(","))
    .join("\r\n");
}

/** Calendar day label (e.g. "4 Nov"), Latin digits in both locales. */
export function dayLabel(
  value: number | string,
  locale: Locale,
  timeZone?: string,
) {
  const date = new Date(value);
  const tag = locale === "fa" ? "fa-IR-u-nu-latn" : "en-GB";
  try {
    return date.toLocaleDateString(tag, {
      month: "short",
      day: "numeric",
      weekday: "short",
      timeZone,
    });
  } catch {
    return date.toLocaleDateString(tag, {
      month: "short",
      day: "numeric",
      weekday: "short",
    });
  }
}

/** Seconds of an outage that fall inside [from, to); ongoing outages end now. */
export function outageSeconds(
  outage: { start: string; end?: string },
  from: string,
  to: string,
  now = Date.now(),
) {
  const a = Math.max(Date.parse(outage.start), Date.parse(from));
  const b = Math.min(outage.end ? Date.parse(outage.end) : now, Date.parse(to));
  return Math.max(0, (b - a) / 1000);
}
