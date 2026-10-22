// What a resolved experience writes onto its scope element (or <html>). Framework-free, so SSR layouts,
// non-React ports and tests use the same functions as <ExperienceScope>.
import type { GeneratedRegistry, ResolvedExperience } from "./types";

/**
 * The attributes a scope carries: selection, every axis as data-<axis>, direction and language.
 * data-mode-preference keeps "system" visible, so a script served from 'self' can settle it before paint.
 */
export function experienceAttributes(
  e: ResolvedExperience,
): Record<string, string> {
  const axes = Object.fromEntries(
    Object.entries(e.axes).map(([k, v]) => [`data-${k}`, v]),
  );
  return {
    "data-surface": e.surface,
    "data-pack": e.pack.id,
    "data-style": e.style.id,
    "data-mode": e.mode,
    "data-mode-preference": e.modePreference,
    ...axes,
    dir: e.dir,
    lang: e.locale,
  };
}

/**
 * Inline CSS variables for JSON-token styles (data packs); CSS styles are applied by the generated, layered
 * stylesheet and return undefined. Inline variables outrank every layer, so a JSON style replays the layers in
 * their order: style tokens, selected axis tokens, then adjustments whose axes all match, least specific first.
 */
export function inlineStyleVars(
  e: ResolvedExperience,
  registry: GeneratedRegistry,
): Record<string, string> | undefined {
  const { style, mode } = e;
  if (style.format !== "json" || !style.tokens) return undefined;
  const map: Record<string, string> =
    mode === "dark"
      ? { ...style.tokens.light, ...style.tokens.dark }
      : { ...style.tokens.light };
  for (const [axis, value] of Object.entries(e.axes)) {
    const t = registry.axes?.[axis]?.tokens[value];
    if (t) Object.assign(map, t.light, mode === "dark" ? t.dark : {});
  }
  const matching = (style.adjustments ?? [])
    .filter((a) => Object.entries(a.axes).every(([k, v]) => e.axes[k] === v))
    .sort((a, b) => Object.keys(a.axes).length - Object.keys(b.axes).length);
  for (const a of matching) Object.assign(map, a[mode]);
  return Object.fromEntries(Object.entries(map).map(([k, v]) => [`--${k}`, v]));
}

/**
 * The same variables as a stylesheet rule, for server-rendered pages under a strict Content-Security-Policy:
 * inline `style` attributes need 'unsafe-inline', but a <style nonce="..."> element (or a cached stylesheet
 * response) does not. Values come from the validated registry; any value that could leave the declaration is
 * dropped as a second line of defense.
 */
export function inlineStyleCss(
  e: ResolvedExperience,
  registry: GeneratedRegistry,
  selector = ":root",
): string {
  const vars = inlineStyleVars(e, registry);
  if (!vars) return "";
  const decls = Object.entries(vars)
    .filter(
      ([k, v]) =>
        /^--[\w-]+$/.test(k) && !/[;{}<>\\]/.test(v) && !v.includes("/*"),
    )
    .map(([k, v]) => `${k}:${v}`);
  return `${selector}{${decls.join(";")}}`;
}
