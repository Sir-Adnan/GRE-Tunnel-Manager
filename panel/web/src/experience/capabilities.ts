// Chooses the template for a page kind given the presentation requirements the adapter derived from domain
// capabilities. Required presentation is never silently dropped: fall back explicitly or block with a diagnostic.
import type {
  Diagnostic,
  GeneratedRegistry,
  PackEntry,
  TemplateEntry,
} from "./types";

export type TemplateChoice =
  | {
      ok: true;
      template: TemplateEntry;
      packId: string;
      fallback: boolean;
      diagnostics: Diagnostic[];
    }
  | { ok: false; missing: string[]; diagnostics: Diagnostic[] };

const missingFrom = (t: TemplateEntry, required: ReadonlySet<string>) =>
  [...required].filter((r) => !t.supports.includes(r));

export function selectTemplate(
  registry: GeneratedRegistry,
  pack: PackEntry,
  pageKind: string,
  required: ReadonlySet<string> = new Set(),
): TemplateChoice {
  const diagnostics: Diagnostic[] = [];
  const surfaceDefault =
    registry.packs[registry.surfaces[pack.surface]?.defaultPackId ?? ""];
  // Selected pack, then the pack it extends, then the surface default pack.
  const chain = [
    pack,
    pack.extends ? registry.packs[pack.extends] : undefined,
    surfaceDefault,
  ].filter(
    (p, i, all): p is PackEntry =>
      !!p && all.findIndex((q) => q?.id === p.id) === i,
  );

  let firstMissing: string[] | null = null;
  for (const [i, p] of chain.entries()) {
    const t = p.templates[pageKind];
    if (!t) continue;
    const missing = missingFrom(t, required);
    if (missing.length === 0) {
      if (i > 0)
        diagnostics.push({
          level: "warn",
          code: "presentation-fallback",
          message: `"${pack.id}" cannot present ${(firstMissing ?? []).join(", ") || pageKind} on "${pageKind}"; using the "${p.id}" template.`,
        });
      return {
        ok: true,
        template: t,
        packId: p.id,
        fallback: i > 0,
        diagnostics,
      };
    }
    firstMissing ??= missing;
  }

  const missing = firstMissing ?? [...required];
  diagnostics.push({
    level: "error",
    code: "presentation-blocked",
    message: `No registered "${pageKind}" template can present: ${missing.join(", ")}. Rendering is blocked instead of hiding required information.`,
  });
  return { ok: false, missing, diagnostics };
}
