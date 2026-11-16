// Text helpers of the Firewall page (kept apart from components for fast refresh).
import { useContext } from "react";
import { LocaleContext } from "@/lib/i18n";
import { number } from "@/lib/format";

/** Replaces {name} placeholders. */
export function fill(text: string, vars: Record<string, string | number>) {
  return text.replace(/\{(\w+)\}/g, (match, key: string) =>
    key in vars ? String(vars[key]) : match,
  );
}

/** Formats counts with the locale's grouping and Latin digits. */
export function useNumber() {
  const locale = useContext(LocaleContext);
  return (value: number) => number(value, locale);
}
