// Runtime validation for Data Packs (level 3 distribution): JSON-only bundles of style tokens and section
// settings layered on an installed code pack. Code is never loaded from a bundle. Run this on the server when a
// bundle is uploaded AND again when it is read back, then keep it in draft until an authorized publish.
import type {
  GeneratedRegistry,
  Mode,
  PackEntry,
  SectionConfig,
  StyleEntry,
} from "./types";

export interface DataPackBundle {
  pack: {
    id: string;
    name: string;
    kind: "data";
    packVersion: string;
    surface: string;
    requires: { contract: string };
    extends: string;
    description?: string;
    defaultStyleId?: string;
    compatibleStyleIds?: string[];
    sections?: Record<string, SectionConfig[]>;
    /** Region id -> variant id; data may choose among installed variants, never ship one. */
    regions?: Record<string, string>;
    limitations?: string[];
  };
  styles?: Array<{
    id: string;
    name: string;
    styleVersion: string;
    surfaces: string[];
    modes: Mode[];
    tokens: { light: Record<string, string>; dark?: Record<string, string> };
  }>;
}

export interface DataPackOptions {
  sectionTypes: readonly string[];
  /** Token names every style must define (light, and dark when declared). Usually the contract's required tokens. */
  requiredTokens?: readonly string[];
  maxBytes?: number;
}

export type DataPackResult =
  | { ok: true; pack: PackEntry; styles: Record<string, StyleEntry> }
  | { ok: false; errors: string[] };

const ID = /^[a-z][a-z0-9-]{0,62}$/;
const SEMVER = /^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?$/;
const PACK_KEYS = new Set([
  "id",
  "name",
  "kind",
  "packVersion",
  "surface",
  "requires",
  "extends",
  "description",
  "defaultStyleId",
  "compatibleStyleIds",
  "sections",
  "regions",
  "limitations",
]);
const STYLE_KEYS = new Set([
  "id",
  "name",
  "styleVersion",
  "surfaces",
  "modes",
  "tokens",
]);

/** Token values: colors, lengths, font stacks, shadows. No CSS structure, url(), imports, or markup. */
export function isSafeTokenValue(v: unknown): v is string {
  if (typeof v !== "string" || v.length > 200) return false;
  if (/[;{}<>\\`]|url\s*\(|expression\s*\(|@import|javascript:/i.test(v))
    return false;
  return /^[\w\s#%.,()/+*'"-]+$/.test(v);
}

/** Supports exact, ^x.y.z, ~x.y.z and >=x.y.z, which is all a data pack needs. */
export function satisfiesContract(version: string, range: string): boolean {
  const v = SEMVER.exec(version);
  const m = /^(\^|~|>=)?\s*(\d+)\.(\d+)\.(\d+)$/.exec(range.trim());
  if (!v || !m) return false;
  const [a, b, c] = [+v[1], +v[2], +v[3]];
  const [x, y, z] = [+m[2], +m[3], +m[4]];
  const gte = a !== x ? a > x : b !== y ? b > y : c >= z;
  if (!m[1]) return a === x && b === y && c === z;
  if (m[1] === ">=") return gte;
  if (m[1] === "~") return gte && a === x && b === y;
  return (
    gte &&
    (x > 0
      ? a === x
      : y > 0
        ? a === 0 && b === y
        : a === 0 && b === 0 && c === z)
  );
}

function checkSettings(
  value: unknown,
  path: string,
  errors: string[],
  depth = 0,
): void {
  if (depth > 5) return void errors.push(`${path}: nested too deeply`);
  if (value === null || typeof value === "number" || typeof value === "boolean")
    return;
  if (typeof value === "string") {
    if (value.length > 5000) errors.push(`${path}: string too long`);
    if (
      /<\s*\/?\s*(script|iframe|object|embed|style)\b|javascript:|data:text\/html|on\w+\s*=/i.test(
        value,
      )
    )
      errors.push(`${path}: markup or script-like content`);
    return;
  }
  if (Array.isArray(value))
    return value.forEach((v, i) =>
      checkSettings(v, `${path}[${i}]`, errors, depth + 1),
    );
  if (typeof value === "object") {
    for (const [k, v] of Object.entries(value as Record<string, unknown>))
      checkSettings(v, `${path}.${k}`, errors, depth + 1);
    return;
  }
  errors.push(`${path}: unsupported value type`);
}

export function validateDataPack(
  input: unknown,
  registry: GeneratedRegistry,
  opts: DataPackOptions,
): DataPackResult {
  const errors: string[] = [];
  const fail = (): DataPackResult => ({ ok: false, errors });

  if (JSON.stringify(input ?? null).length > (opts.maxBytes ?? 256 * 1024))
    return (errors.push("bundle too large"), fail());
  if (!input || typeof input !== "object")
    return (errors.push("bundle must be an object"), fail());
  const bundle = input as DataPackBundle;
  const p = bundle.pack as DataPackBundle["pack"] | undefined;
  if (!p || typeof p !== "object") return (errors.push("missing pack"), fail());

  for (const k of Object.keys(p))
    if (!PACK_KEYS.has(k))
      errors.push(
        `pack.${k}: unknown field (data packs cannot declare shell, templates or assets)`,
      );
  if (p.kind !== "data") errors.push('pack.kind must be "data"');
  if (!ID.test(p.id ?? "")) errors.push("pack.id is invalid");
  if (typeof p.name !== "string" || !p.name || p.name.length > 80)
    errors.push("pack.name is required (max 80 chars)");
  if (!SEMVER.test(p.packVersion ?? ""))
    errors.push("pack.packVersion must be semver");
  if (Object.hasOwn(registry.packs, p.id))
    errors.push(`pack.id "${p.id}" collides with an installed code pack`);
  const surfaceDef = Object.hasOwn(registry.surfaces, p.surface)
    ? registry.surfaces[p.surface]
    : undefined;
  if (!surfaceDef) errors.push(`pack.surface "${p.surface}" does not exist`);
  if (
    typeof p.requires?.contract !== "string" ||
    !satisfiesContract(registry.contractVersion, p.requires.contract)
  )
    errors.push(
      `pack.requires.contract "${p.requires?.contract}" is not satisfied by host contract ${registry.contractVersion}`,
    );

  const base = Object.hasOwn(registry.packs, p.extends)
    ? registry.packs[p.extends]
    : undefined;
  if (!base)
    errors.push(`pack.extends "${p.extends}" is not an installed pack`);
  else if (base.kind !== "code" || base.extends)
    errors.push(
      `pack.extends "${p.extends}" must be a code pack that does not extend another pack`,
    );
  else if (base.surface !== p.surface)
    errors.push(`pack.extends "${p.extends}" is on surface "${base.surface}"`);

  // Styles shipped in the bundle: JSON tokens only, new ids only.
  const styles: Record<string, StyleEntry> = {};
  for (const [i, s] of (bundle.styles ?? []).entries()) {
    const w = `styles[${i}]`;
    for (const k of Object.keys(s))
      if (!STYLE_KEYS.has(k)) errors.push(`${w}.${k}: unknown field`);
    if (!ID.test(s.id ?? "")) {
      errors.push(`${w}.id is invalid`);
      continue;
    }
    if (Object.hasOwn(registry.styles, s.id) || styles[s.id])
      errors.push(`${w}.id "${s.id}" collides with an installed style`);
    if (!SEMVER.test(s.styleVersion ?? ""))
      errors.push(`${w}.styleVersion must be semver`);
    if (!Array.isArray(s.surfaces) || !s.surfaces.includes(p.surface))
      errors.push(`${w}.surfaces must include "${p.surface}"`);
    const modes = Array.isArray(s.modes)
      ? s.modes.filter((m): m is Mode => m === "light" || m === "dark")
      : [];
    if (!modes.length || modes.length !== s.modes.length)
      errors.push(`${w}.modes must be "light" and/or "dark"`);
    for (const mode of modes) {
      const map = s.tokens?.[mode];
      if (!map || typeof map !== "object") {
        errors.push(`${w}.tokens.${mode} is missing`);
        continue;
      }
      for (const [name, value] of Object.entries(map)) {
        if (!/^[a-z][a-z0-9-]*$/.test(name))
          errors.push(`${w}.tokens.${mode}.${name}: invalid token name`);
        if (!isSafeTokenValue(value))
          errors.push(`${w}.tokens.${mode}.${name}: unsafe value`);
      }
      const effective = mode === "dark" ? { ...s.tokens.light, ...map } : map;
      const missing = (opts.requiredTokens ?? []).filter(
        (t) => effective[t] === undefined,
      );
      if (missing.length)
        errors.push(
          `${w}.tokens.${mode} is missing required token(s): ${missing.join(", ")}`,
        );
    }
    styles[s.id] = {
      id: s.id,
      name: s.name,
      styleVersion: s.styleVersion,
      surfaces: s.surfaces,
      modes,
      format: "json",
      tokens: s.tokens,
    };
  }

  const known = (id: string) =>
    Object.hasOwn(registry.styles, id) || Object.hasOwn(styles, id);
  const defaultStyleId = p.defaultStyleId ?? base?.defaultStyleId ?? "";
  const compatibleStyleIds = [
    ...new Set([
      defaultStyleId,
      ...(p.compatibleStyleIds ?? base?.compatibleStyleIds ?? []),
    ]),
  ];
  for (const id of compatibleStyleIds)
    if (!known(id))
      errors.push(
        `style "${id}" is neither installed nor shipped in the bundle`,
      );

  const pageKinds = new Set([
    ...(surfaceDef?.requiredPageKinds ?? []),
    ...(surfaceDef?.optionalPageKinds ?? []),
  ]);
  for (const [pk, list] of Object.entries(p.sections ?? {})) {
    if (!pageKinds.has(pk)) errors.push(`sections.${pk}: unknown page kind`);
    if (!Array.isArray(list)) {
      errors.push(`sections.${pk} must be an array`);
      continue;
    }
    list.forEach((sec, i) => {
      if (!opts.sectionTypes.includes(sec?.type))
        errors.push(
          `sections.${pk}[${i}].type "${sec?.type}" is not a registered section type`,
        );
      for (const k of Object.keys(sec ?? {}))
        if (k !== "type" && k !== "settings")
          errors.push(`sections.${pk}[${i}].${k}: unknown field`);
      if (sec?.settings !== undefined)
        checkSettings(sec.settings, `sections.${pk}[${i}].settings`, errors);
    });
  }
  for (const [region, variant] of Object.entries(p.regions ?? {})) {
    const def = Object.hasOwn(registry.regions ?? {}, region)
      ? registry.regions![region]
      : undefined;
    if (!def) errors.push(`regions.${region}: not a registered region`);
    else if (def.surface !== p.surface)
      errors.push(
        `regions.${region}: region belongs to surface "${def.surface}"`,
      );
    else if (
      typeof variant !== "string" ||
      !Object.hasOwn(def.variants, variant)
    )
      errors.push(
        `regions.${region}: "${variant}" is not an installed variant`,
      );
  }
  if (
    p.limitations?.some((l) => /a11y|accessib|contrast|keyboard|focus/i.test(l))
  )
    errors.push("accessibility cannot be a pack limitation");

  if (errors.length || !base) return fail();
  return {
    ok: true,
    styles,
    pack: {
      id: p.id,
      name: p.name,
      kind: "data",
      surface: p.surface,
      packVersion: p.packVersion,
      extends: base.id,
      defaultStyleId,
      compatibleStyleIds,
      shell: base.shell,
      templates: base.templates,
      sections: { ...base.sections, ...(p.sections ?? {}) },
      regions: { ...(base.regions ?? {}), ...(p.regions ?? {}) },
      limitations: p.limitations ?? [],
    },
  };
}
