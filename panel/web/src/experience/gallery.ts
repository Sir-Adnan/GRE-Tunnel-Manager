// Picker data from the registry alone: the styles, packs or region variants a viewer may choose, grouped in the
// registry's group order, named in the viewer's language, with swatches for previews. Framework-free, and it
// needs no stylesheet, so a picker can show lazy styles before loading them.
import type {
  GalleryMeta,
  GeneratedRegistry,
  Swatches,
  Translations,
} from "./types";

export interface GalleryItem {
  id: string;
  name: string;
  description?: string;
  tags: readonly string[];
  swatches?: Swatches;
  /** Deprecated entries are listed only when current (or when asked), so a viewer still sees their choice. */
  deprecated: boolean;
  current: boolean;
}

export interface GalleryGroup {
  /** null collects entries without a group (or with a group the registry does not know). */
  id: string | null;
  name: string;
  items: GalleryItem[];
}

export interface GalleryOptions {
  locale: string;
  current?: string;
  includeDeprecated?: boolean;
  /** Name of the group collecting ungrouped entries. */
  otherLabel?: string;
}

/**
 * Name and description in `locale`: an exact translation, then the language alone ("pt-BR" -> "pt"), then
 * the entry's own text (the registry's first locale).
 */
export function localize(
  entry: { name: string; description?: string; i18n?: Translations },
  locale: string,
): { name: string; description?: string } {
  const t = entry.i18n?.[locale] ?? entry.i18n?.[locale.split("-")[0]];
  return {
    name: t?.name ?? entry.name,
    description: t?.description ?? entry.description,
  };
}

type Candidate = GalleryMeta & {
  id: string;
  name: string;
  deprecated?: unknown;
  swatches?: Swatches;
};

function gallery(
  registry: GeneratedRegistry,
  candidates: readonly Candidate[],
  o: GalleryOptions,
): GalleryGroup[] {
  const collator = new Intl.Collator(o.locale);
  const groups = new Map<string | null, GalleryGroup>();
  for (const [id, g] of Object.entries(registry.groups ?? {}))
    groups.set(id, { id, name: localize(g, o.locale).name, items: [] });
  const other: GalleryGroup = {
    id: null,
    name: o.otherLabel ?? "Other",
    items: [],
  };

  for (const c of candidates) {
    const current = c.id === o.current;
    if (c.deprecated && !current && !o.includeDeprecated) continue;
    const { name, description } = localize(c, o.locale);
    const item: GalleryItem = {
      id: c.id,
      name,
      description,
      tags: c.tags ?? [],
      swatches: c.swatches,
      deprecated: !!c.deprecated,
      current,
    };
    (groups.get(c.group ?? null) ?? other).items.push(item);
  }
  return [...groups.values(), other]
    .filter((g) => g.items.length)
    .map((g) => ({
      ...g,
      items: g.items.sort((a, b) => collator.compare(a.name, b.name)),
    }));
}

/** Styles for a surface; with `packId`, only those the pack accepts (what the resolver would allow). */
export function styleGallery(
  registry: GeneratedRegistry,
  o: GalleryOptions & { surface: string; packId?: string },
): GalleryGroup[] {
  const allowed = o.packId
    ? new Set(registry.packs[o.packId]?.compatibleStyleIds ?? [])
    : null;
  const styles = Object.values(registry.styles).filter(
    (s) => s.surfaces.includes(o.surface) && (!allowed || allowed.has(s.id)),
  );
  return gallery(registry, styles, o);
}

export function packGallery(
  registry: GeneratedRegistry,
  o: GalleryOptions & { surface: string },
): GalleryGroup[] {
  return gallery(
    registry,
    Object.values(registry.packs).filter((p) => p.surface === o.surface),
    o,
  );
}

export function regionGallery(
  registry: GeneratedRegistry,
  o: GalleryOptions & { region: string },
): GalleryGroup[] {
  return gallery(
    registry,
    Object.values(registry.regions?.[o.region]?.variants ?? {}),
    o,
  );
}
