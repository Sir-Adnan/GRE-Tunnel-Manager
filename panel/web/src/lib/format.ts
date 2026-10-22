import type { Locale } from "./i18n";

export function number(
  value: number,
  locale: Locale,
  maximumFractionDigits = 0,
) {
  return new Intl.NumberFormat(locale === "fa" ? "fa-IR" : "en-US", {
    maximumFractionDigits,
  }).format(value);
}

export function trafficBytes(value: number, locale: Locale) {
  const unit =
    value > 0 ? Math.min(Math.floor(Math.log(value) / Math.log(1024)), 4) : 0;
  return `${number(value / 1024 ** unit, locale, 1)} ${["B", "KiB", "MiB", "GiB", "TiB"][unit]}`;
}

export function engineName(engine: string) {
  return (
    (
      {
        haproxy: "HAProxy",
        realm: "Realm",
        nftables: "nftables",
        iptables: "iptables",
        gre: "GRE",
        frp: "FRP",
        rathole: "rathole",
      } as Record<string, string>
    )[engine] || engine
  );
}

export function uptime(value: string, locale: Locale) {
  const matches = [...value.matchAll(/(\d+(?:\.\d+)?)(h|m|s)/g)];
  if (!matches.length) return value || "—";
  const labels =
    locale === "fa"
      ? { h: "ساعت", m: "دقیقه", s: "ثانیه" }
      : { h: "h", m: "m", s: "s" };
  const parts = matches.filter(([, v]) => Number(v) > 0).slice(0, 2);
  return (parts.length ? parts : matches.slice(-1))
    .map(
      ([, v, unit]) =>
        `${number(Number(v), locale)} ${labels[unit as keyof typeof labels]}`,
    )
    .join(" · ");
}
