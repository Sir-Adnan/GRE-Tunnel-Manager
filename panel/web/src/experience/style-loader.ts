// On-demand style stylesheets (gen-registry --lazy-styles). A style with a `css` loader is painted only after
// its stylesheet has loaded, so switching never shows the new attributes over missing tokens. Styles without a
// loader are in the eager stylesheet and are always ready. Framework-free; ExperienceScope uses it.
import type { GeneratedRegistry } from "./types";

type CssLoader = () => Promise<unknown>;
const loaded = new WeakSet<CssLoader>();
const pending = new WeakMap<CssLoader, Promise<void>>();

export function isStyleReady(
  registry: GeneratedRegistry,
  styleId: string,
): boolean {
  const css = registry.styles[styleId]?.css;
  return !css || loaded.has(css);
}

/** Loads a style's stylesheet once; concurrent calls share one request, and a failure can be retried. */
export function loadStyle(
  registry: GeneratedRegistry,
  styleId: string,
): Promise<void> {
  const css = registry.styles[styleId]?.css;
  if (!css || loaded.has(css)) return Promise.resolve();
  let p = pending.get(css);
  if (!p) {
    p = css().then(
      () => {
        loaded.add(css);
        pending.delete(css);
      },
      (error: unknown) => {
        pending.delete(css);
        throw error;
      },
    );
    pending.set(css, p);
  }
  return p;
}

/** Warm the stylesheets a picker is about to offer (on open or hover), so choosing one paints at once. */
export function preloadStyles(
  registry: GeneratedRegistry,
  styleIds: Iterable<string>,
): Promise<void> {
  return Promise.all(
    [...styleIds].map((id) => loadStyle(registry, id).catch(() => undefined)),
  ).then(() => undefined);
}
