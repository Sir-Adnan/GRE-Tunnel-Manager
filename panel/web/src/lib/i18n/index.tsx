import { createContext, useContext } from "react";
import type { Locale } from "@/lib/preferences";
import { messages } from "./messages";

export type { Locale };
export const LocaleContext = createContext<Locale>("en");
export type Key = keyof typeof messages;

/** Unknown keys are returned unchanged, so dynamic values (engine ids, states) still render. */
export function translate(locale: Locale, key: string): string {
  return Object.hasOwn(messages, key)
    ? messages[key as Key][locale === "fa" ? 1 : 0]
    : key;
}
export function useT() {
  const locale = useContext(LocaleContext);
  return (key: string) => translate(locale, key);
}
