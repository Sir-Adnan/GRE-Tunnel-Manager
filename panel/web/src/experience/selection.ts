// Parses and migrates persisted selections. Shape is validated; IDs are kept as strings and resolved later,
// so a temporarily missing pack does not erase the user's valid choice. Nothing here becomes a path or selector.
import type {
  ModePreference,
  PersistedSelection,
  SurfaceSelection,
} from "./types";

export const ID_PATTERN = /^[a-z][a-z0-9-]{0,62}$/;
const MODES: readonly ModePreference[] = ["light", "dark", "system"];

/** Project-specific mapping from a legacy appearance value to the current contract. */
export type LegacyMap = Record<
  string,
  { surface: string; selection: SurfaceSelection }
>;

export interface ParseResult {
  selection: PersistedSelection;
  migrated: boolean;
  warnings: string[];
  /** Original value kept for a compatibility/rollback window when migration happened. */
  legacy?: unknown;
}

function cleanSurface(
  raw: unknown,
  where: string,
  warnings: string[],
): SurfaceSelection {
  const out: SurfaceSelection = {};
  if (!raw || typeof raw !== "object") return out;
  const r = raw as Record<string, unknown>;
  for (const key of ["packId", "styleId"] as const) {
    const v = r[key];
    if (v === undefined) continue;
    if (typeof v === "string" && ID_PATTERN.test(v)) out[key] = v;
    else warnings.push(`${where}.${key} is not a valid id and was ignored`);
  }
  if (r.mode !== undefined) {
    if (MODES.includes(r.mode as ModePreference))
      out.mode = r.mode as ModePreference;
    else warnings.push(`${where}.mode is invalid and was ignored`);
  }
  for (const key of ["axes", "regions"] as const) {
    if (r[key] === undefined) continue;
    const map = cleanIdMap(r[key], `${where}.${key}`, warnings);
    if (Object.keys(map).length) out[key] = map;
  }
  return out;
}

/** { id: id } maps (axis values, region variants); invalid entries are dropped with a warning. */
function cleanIdMap(
  raw: unknown,
  where: string,
  warnings: string[],
): Record<string, string> {
  const out: Record<string, string> = {};
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    warnings.push(`${where} is not an object and was ignored`);
    return out;
  }
  for (const [k, v] of Object.entries(raw as Record<string, unknown>)) {
    if (ID_PATTERN.test(k) && typeof v === "string" && ID_PATTERN.test(v))
      out[k] = v;
    else warnings.push(`${where}.${k} is not a valid id pair and was ignored`);
  }
  return out;
}

export function parseSelection(
  raw: unknown,
  currentSchemaVersion: number,
  legacyMap: LegacyMap = {},
): ParseResult {
  const warnings: string[] = [];
  const empty: PersistedSelection = {
    schemaVersion: currentSchemaVersion,
    surfaces: {},
  };
  if (!raw || typeof raw !== "object")
    return {
      selection: empty,
      migrated: false,
      warnings: raw == null ? [] : ["selection is not an object"],
    };
  const r = raw as Record<string, unknown>;

  // Legacy single-value setting, e.g. { theme: "legacy-dark" }.
  if (r.schemaVersion === undefined && typeof r.theme === "string") {
    const mapped = legacyMap[r.theme];
    if (!mapped) {
      warnings.push(
        `legacy theme "${r.theme}" has no mapping; defaults apply and the old value is kept`,
      );
      return { selection: empty, migrated: false, warnings, legacy: raw };
    }
    const sel = cleanSurface(mapped.selection, `legacy.${r.theme}`, warnings);
    return {
      selection: {
        schemaVersion: currentSchemaVersion,
        surfaces: { [mapped.surface]: sel },
      },
      migrated: true,
      warnings,
      legacy: raw,
    };
  }

  if (typeof r.schemaVersion !== "number")
    return {
      selection: empty,
      migrated: false,
      warnings: ["missing schemaVersion"],
      legacy: raw,
    };
  if (r.schemaVersion > currentSchemaVersion)
    return {
      selection: empty,
      migrated: false,
      warnings: [
        `schemaVersion ${r.schemaVersion} is newer than supported ${currentSchemaVersion}`,
      ],
      legacy: raw,
    };
  // Add step-wise migrations here when the shape changes: if (r.schemaVersion === 1) { ...; }

  const surfaces: Record<string, SurfaceSelection> = {};
  const rawSurfaces =
    r.surfaces && typeof r.surfaces === "object"
      ? (r.surfaces as Record<string, unknown>)
      : {};
  for (const [name, value] of Object.entries(rawSurfaces)) {
    if (!ID_PATTERN.test(name)) {
      warnings.push(`surface key "${name}" is invalid and was ignored`);
      continue;
    }
    surfaces[name] = cleanSurface(value, `surfaces.${name}`, warnings);
  }
  return {
    selection: { schemaVersion: currentSchemaVersion, surfaces },
    migrated: r.schemaVersion !== currentSchemaVersion,
    warnings,
  };
}

export function serializeSelection(selection: PersistedSelection): string {
  return JSON.stringify(selection);
}
