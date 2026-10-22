// Resolves the effective experience for one surface, once, at the surface root.
//
// Precedence (most specific first, each candidate validated before it is used):
//   pack    site choice -> surface default pack
//   style   user (if allowed) -> site -> pack default -> surface default pack's default
//   mode    user (if allowed) -> site -> "system"
//   axis    user (if the axis and the product allow) -> site (unless overridableBy "none") -> style preference -> axis default
//   region  site -> pack default -> region default
// Retired ids follow registry aliases. Unknown, retired-without-alias or incompatible ids fall back with a
// diagnostic; they never become import paths, selectors or class names.
import type {
  AxisEntry,
  Diagnostic,
  Direction,
  GeneratedRegistry,
  Mode,
  ModePreference,
  PackEntry,
  ResolvedExperience,
  StyleEntry,
  SurfaceSelection,
} from "./types";

export interface ResolveInput {
  registry: GeneratedRegistry;
  surface: string;
  /** Published site/administrator selection for this surface. */
  site?: SurfaceSelection;
  /** Per-user preference. Only fields enabled in `userMay` are honored. */
  user?: SurfaceSelection;
  /** `axes: true` allows every axis whose overridableBy is "user"; a list allows only those axes. */
  userMay?: {
    style?: boolean;
    mode?: boolean;
    axes?: boolean | readonly string[];
  };
  /** Whether the client prefers dark; pass undefined on the server to keep "system" as light until hydration. */
  systemPrefersDark?: boolean;
  locale: string;
  /** Explicit direction; otherwise derived from the locale. Never derived from the style or pack. */
  dir?: Direction;
  /** Additional packs installed at runtime (validated data packs), keyed by id. */
  runtimePacks?: Readonly<Record<string, PackEntry>>;
  runtimeStyles?: Readonly<Record<string, StyleEntry>>;
}

const RTL_LANGS = new Set([
  "ar",
  "fa",
  "he",
  "ur",
  "ps",
  "ckb",
  "dv",
  "yi",
  "sd",
  "ug",
  "ku",
]);

export function directionFor(locale: string): Direction {
  return RTL_LANGS.has(locale.toLowerCase().split(/[-_]/)[0]) ? "rtl" : "ltr";
}

const own = <T>(
  record: Readonly<Record<string, T>> | undefined,
  key: string | undefined,
): T | undefined =>
  record && key !== undefined && Object.hasOwn(record, key)
    ? record[key]
    : undefined;

/** Maps a retired id to its successor, with a note; returns the id unchanged otherwise. */
function canonical(
  aliases: Readonly<Record<string, string>> | undefined,
  id: string | undefined,
  kind: string,
  diagnostics: Diagnostic[],
  label = kind,
) {
  const successor = own(aliases, id);
  if (id === undefined || successor === undefined) return id;
  diagnostics.push({
    level: "info",
    code: `${kind}-alias`,
    message: `${label} "${id}" was retired; using its successor "${successor}".`,
  });
  return successor;
}

function noteDeprecated(
  entry: { id: string; deprecated?: { replacedBy?: string } },
  kind: string,
  diagnostics: Diagnostic[],
  label = kind,
) {
  if (!entry.deprecated) return;
  const by = entry.deprecated.replacedBy
    ? `; prefer "${entry.deprecated.replacedBy}"`
    : "";
  diagnostics.push({
    level: "info",
    code: `${kind}-deprecated`,
    message: `${label} "${entry.id}" is deprecated${by}.`,
  });
}

export function resolveExperience(input: ResolveInput): ResolvedExperience {
  const { registry, surface } = input;
  const diagnostics: Diagnostic[] = [];
  const surfaceDef = own(registry.surfaces, surface);
  if (!surfaceDef)
    throw new Error(
      `Unknown surface "${surface}": add it to experience.contract.json and regenerate the registry.`,
    );

  const packs = { ...registry.packs, ...input.runtimePacks };
  const styles = { ...registry.styles, ...input.runtimeStyles };
  const fallbackPack = own(registry.packs, surfaceDef.defaultPackId);
  if (!fallbackPack)
    throw new Error(
      `Default pack "${surfaceDef.defaultPackId}" for surface "${surface}" is not registered.`,
    );

  const pack = resolvePack(input, packs, fallbackPack, diagnostics);
  const style = resolveStyle(input, styles, pack, fallbackPack, diagnostics);

  const modePreference: ModePreference =
    (input.userMay?.mode ? input.user?.mode : undefined) ??
    input.site?.mode ??
    "system";
  let mode: Mode =
    modePreference === "system"
      ? input.systemPrefersDark
        ? "dark"
        : "light"
      : modePreference;
  if (!style.modes.includes(mode)) {
    diagnostics.push({
      level: "info",
      code: "mode-unsupported",
      message: `Style "${style.id}" has no ${mode} mode; using ${style.modes[0]}.`,
    });
    mode = style.modes[0];
  }

  return {
    surface,
    pack,
    style,
    mode,
    modePreference,
    axes: resolveAxes(input, style, diagnostics),
    regions: resolveRegions(input, pack, diagnostics),
    dir: input.dir ?? directionFor(input.locale),
    locale: input.locale,
    diagnostics,
  };
}

function resolvePack(
  input: ResolveInput,
  packs: Readonly<Record<string, PackEntry>>,
  fallback: PackEntry,
  diagnostics: Diagnostic[],
): PackEntry {
  const wanted = canonical(
    input.registry.aliases?.packs,
    input.site?.packId,
    "pack",
    diagnostics,
  );
  if (!wanted || wanted === fallback.id) return fallback;
  const candidate = own(packs, wanted);
  if (!candidate) {
    diagnostics.push({
      level: "warn",
      code: "pack-unknown",
      message: `Pack "${wanted}" is not installed; using "${fallback.id}".`,
    });
    return fallback;
  }
  if (candidate.surface !== input.surface) {
    diagnostics.push({
      level: "warn",
      code: "pack-surface",
      message: `Pack "${wanted}" belongs to "${candidate.surface}"; using "${fallback.id}".`,
    });
    return fallback;
  }
  noteDeprecated(candidate, "pack", diagnostics);
  return candidate;
}

function resolveStyle(
  input: ResolveInput,
  styles: Readonly<Record<string, StyleEntry>>,
  pack: PackEntry,
  fallbackPack: PackEntry,
  diagnostics: Diagnostic[],
): StyleEntry {
  const aliases = input.registry.aliases?.styles;
  // First acceptable candidate wins, most specific first.
  const candidates: Array<[string | undefined, string]> = [
    [input.userMay?.style ? input.user?.styleId : undefined, "user"],
    [input.site?.styleId, "site"],
    [pack.defaultStyleId, "pack default"],
    [fallbackPack.defaultStyleId, "surface default"],
  ];
  for (const [raw, origin] of candidates) {
    const id = canonical(aliases, raw, "style", diagnostics);
    if (!id) continue;
    const s = own(styles, id);
    if (!s)
      diagnostics.push({
        level: "warn",
        code: "style-unknown",
        message: `Style "${id}" (${origin}) is not installed.`,
      });
    else if (!s.surfaces.includes(input.surface))
      diagnostics.push({
        level: "warn",
        code: "style-surface",
        message: `Style "${id}" (${origin}) does not support "${input.surface}".`,
      });
    else if (!pack.compatibleStyleIds.includes(id))
      diagnostics.push({
        level: "info",
        code: "style-incompatible",
        message: `Style "${id}" (${origin}) is not compatible with pack "${pack.id}".`,
      });
    else {
      noteDeprecated(s, "style", diagnostics);
      return s;
    }
  }
  throw new Error(
    `No usable style for pack "${pack.id}" on "${input.surface}". The registry should have prevented this.`,
  );
}

function userMayTune(input: ResolveInput, axis: AxisEntry): boolean {
  const allowed = input.userMay?.axes;
  return (
    axis.overridableBy === "user" &&
    (allowed === true || (Array.isArray(allowed) && allowed.includes(axis.id)))
  );
}

function resolveAxes(
  input: ResolveInput,
  style: StyleEntry,
  diagnostics: Diagnostic[],
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const axis of Object.values(input.registry.axes ?? {})) {
    if (axis.surfaces && !axis.surfaces.includes(input.surface)) continue;
    const candidates: Array<[string | undefined, string]> = [
      [
        userMayTune(input, axis) ? own(input.user?.axes, axis.id) : undefined,
        "user",
      ],
      [
        axis.overridableBy !== "none"
          ? own(input.site?.axes, axis.id)
          : undefined,
        "site",
      ],
      [own(style.axes, axis.id), `style "${style.id}"`],
    ];
    out[axis.id] = axis.default;
    for (const [value, origin] of candidates) {
      if (value === undefined) continue;
      if (axis.values.includes(value)) {
        out[axis.id] = value;
        break;
      }
      diagnostics.push({
        level: "warn",
        code: "axis-value",
        message: `Axis "${axis.id}" has no value "${value}" (${origin}); ignored.`,
      });
    }
  }
  return out;
}

function resolveRegions(
  input: ResolveInput,
  pack: PackEntry,
  diagnostics: Diagnostic[],
): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [id, region] of Object.entries(input.registry.regions ?? {})) {
    if (region.surface !== input.surface) continue;
    const aliases = own(input.registry.aliases?.regions, id);
    const candidates: Array<[string | undefined, string]> = [
      [own(input.site?.regions, id), "site"],
      [own(pack.regions, id), `pack "${pack.id}"`],
    ];
    out[id] = region.default;
    for (const [raw, origin] of candidates) {
      const variant = canonical(
        aliases,
        raw,
        "region",
        diagnostics,
        `region "${id}" variant`,
      );
      if (variant === undefined) continue;
      const entry = own(region.variants, variant);
      if (!entry) {
        diagnostics.push({
          level: "warn",
          code: "region-unknown",
          message: `Region "${id}" has no variant "${variant}" (${origin}); using "${region.default}".`,
        });
        continue;
      }
      noteDeprecated(entry, "region", diagnostics, `region "${id}" variant`);
      out[id] = variant;
      break;
    }
  }
  return out;
}
