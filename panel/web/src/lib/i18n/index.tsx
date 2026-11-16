import { createContext, useContext } from "react";
import type { Locale } from "@/lib/preferences";
import { errorText } from "@/lib/server-messages";
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
/**
 * The text of a thrown value in the interface language (see
 * lib/server-messages.ts). It reads the language from the document root, which
 * App keeps in step with the preference, so hooks and helpers outside a
 * component can use it too.
 */
export function errorMessage(error: unknown): string {
  const locale: Locale =
    globalThis.document?.documentElement.lang === "en" ? "en" : "fa";
  return errorText(error, (key) => translate(locale, key));
}
