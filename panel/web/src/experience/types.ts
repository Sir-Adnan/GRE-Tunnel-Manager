// Experience system contracts. Narrow the string unions to your project's surfaces and page kinds.
import type { ComponentType, ReactNode } from "react";

export type Mode = "light" | "dark";
export type ModePreference = Mode | "system";
export type Direction = "ltr" | "rtl";

export interface ShellProps {
  children?: ReactNode;
}

/** Props every page template receives. `M` is the page-family presentation model (define per family). */
export interface TemplateProps<K extends string = string, M = unknown> {
  pageKind: K;
  model: M;
}

/** Props every region variant receives: the same model whichever variant is selected. */
export interface RegionProps<M = unknown> {
  region: string;
  model: M;
}

export type ModuleLoader<P> = () => Promise<{ default: ComponentType<P> }>;

/** Marks an entry that still works but should no longer be chosen; pickers hide it. */
export interface Deprecation {
  since?: string;
  replacedBy?: string;
  reason?: string;
}

/** Translated picker text per BCP 47 locale; `name` on the entry is in the registry's first locale. */
export type Translations = Readonly<
  Record<string, { name?: string; description?: string }>
>;

/** Picker metadata shared by styles, packs and region variants (see gallery.ts). */
export interface GalleryMeta {
  description?: string;
  /** One of the registry's groups. */
  group?: string;
  tags?: readonly string[];
  i18n?: Translations;
}

export interface GroupEntry {
  id: string;
  name: string;
  description?: string;
  i18n?: Translations;
}

/** Key colors per mode as hex, resolved at build time: picker previews without loading the style. */
export type Swatches = Readonly<Partial<Record<Mode, TokenMap>>>;

export interface TemplateEntry {
  /** Pack that owns this template (differs from the selected pack when inherited via `extends`). */
  from: string;
  /** Presentation requirements this template can render. Grants no business capability. */
  supports: readonly string[];
  load: ModuleLoader<TemplateProps<any, any>>;
}

export interface SectionConfig {
  type: string;
  settings?: Record<string, unknown>;
}

export type TokenMap = Readonly<Record<string, string>>;

export interface StyleEntry extends GalleryMeta {
  id: string;
  name: string;
  styleVersion: string;
  surfaces: readonly string[];
  modes: readonly Mode[];
  /** css: compiled into the app. json: values applied as inline CSS variables (data packs, runtime installs). */
  format: "css" | "json";
  tokens?: { light: TokenMap; dark?: TokenMap };
  /** JSON styles only: generated contrast fixes and derived tokens, per axis combination ({} is the base). */
  adjustments?: ReadonlyArray<{
    axes: Readonly<Record<string, string>>;
    light?: TokenMap;
    dark?: TokenMap;
  }>;
  /** The style's preferred value per axis (density, sidebar...), used when nobody chose one. */
  axes?: Readonly<Record<string, string>>;
  deprecated?: Deprecation;
  swatches?: Swatches;
  /** Present when the style's stylesheet loads on demand (gen-registry --lazy-styles); see style-loader.ts. */
  css?: () => Promise<unknown>;
}

export interface PackEntry extends GalleryMeta {
  id: string;
  name: string;
  kind: "code" | "data";
  surface: string;
  packVersion: string;
  extends: string | null;
  defaultStyleId: string;
  compatibleStyleIds: readonly string[];
  shell: ModuleLoader<ShellProps> | null;
  templates: Readonly<Record<string, TemplateEntry>>;
  sections: Readonly<Record<string, readonly SectionConfig[]>>;
  /** Default variant per region for this pack (own or inherited). */
  regions?: Readonly<Record<string, string>>;
  limitations: readonly string[];
  deprecated?: Deprecation;
}

/**
 * A closed set of choices written as data-<id> on the scope: layout composition (density, sidebar, tabs) or
 * personal tuning (accent, scale). Values may carry token overrides, applied by the generated CSS.
 */
export interface AxisEntry {
  id: string;
  values: readonly string[];
  default: string;
  /** Who may override the style's preference: nobody, the site owner, or each user (when the product allows). */
  overridableBy: "none" | "site" | "user";
  /** Surfaces the axis applies to; null means every surface. */
  surfaces: readonly string[] | null;
  tokens: Readonly<Record<string, { light: TokenMap; dark: TokenMap }>>;
}

export interface RegionVariantEntry extends GalleryMeta {
  id: string;
  name: string;
  deprecated?: Deprecation;
  load: ModuleLoader<RegionProps<any>> | null;
}

/** One named part of a page whose design is chosen independently of the pack (e.g. a subscription hero). */
export interface RegionEntry {
  surface: string;
  default: string;
  variants: Readonly<Record<string, RegionVariantEntry>>;
}

/** Retired id -> successor, so stored selections keep resolving after a folder is removed. */
export interface RegistryAliases {
  styles: Readonly<Record<string, string>>;
  packs: Readonly<Record<string, string>>;
  regions: Readonly<Record<string, Readonly<Record<string, string>>>>;
}

export interface SurfaceDefinition {
  defaultPackId: string;
  requiredPageKinds: readonly string[];
  optionalPageKinds: readonly string[];
}

/** Shape of registry.generated.ts (produced by scripts/gen-registry.mjs). */
export interface GeneratedRegistry {
  contractVersion: string;
  selectionSchemaVersion: number;
  surfaces: Readonly<Record<string, SurfaceDefinition>>;
  styles: Readonly<Record<string, StyleEntry>>;
  packs: Readonly<Record<string, PackEntry>>;
  // The fields below are optional so registries generated by earlier versions still type-check.
  /** Locales pickers are translated into; the first is the language of every `name`. */
  locales?: readonly string[];
  /** Gallery groups in display order. */
  groups?: Readonly<Record<string, GroupEntry>>;
  axes?: Readonly<Record<string, AxisEntry>>;
  regions?: Readonly<Record<string, RegionEntry>>;
  aliases?: RegistryAliases;
}

/** One surface's choice. Only registered IDs are meaningful; unknown IDs resolve to safe defaults. */
export interface SurfaceSelection {
  packId?: string;
  styleId?: string;
  mode?: ModePreference;
  /** Axis id -> value. Only explicit choices are stored, so a later change of a default reaches everyone else. */
  axes?: Readonly<Record<string, string>>;
  /** Region id -> variant id. */
  regions?: Readonly<Record<string, string>>;
}

/** Persisted visual configuration (site-wide, or per user for the fields the product exposes). */
export interface PersistedSelection {
  schemaVersion: number;
  surfaces: Record<string, SurfaceSelection>;
}

export interface Diagnostic {
  level: "info" | "warn" | "error";
  code: string;
  message: string;
}

export interface ResolvedExperience {
  surface: string;
  pack: PackEntry;
  style: StyleEntry;
  mode: Mode;
  modePreference: ModePreference;
  /** Effective value of every axis that applies to this surface. */
  axes: Readonly<Record<string, string>>;
  /** Effective variant of every region on this surface. */
  regions: Readonly<Record<string, string>>;
  dir: Direction;
  locale: string;
  diagnostics: Diagnostic[];
}
