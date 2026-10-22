"use client"; // a client component in React Server Components frameworks (Next.js App Router); ignored elsewhere
/* eslint-disable react/only-export-components -- This context boundary intentionally exports its companion hooks. */
// Applies a resolved experience to a subtree and renders page templates and region variants through the registry.
// Portals (dialogs, popovers, toasts) must render inside the scope to inherit tokens and direction:
// pass usePortalContainer() to Radix/shadcn `container` props, or use applyToDocument for single-surface pages.
import {
  createContext,
  lazy,
  Suspense,
  useContext,
  useEffect,
  useMemo,
  useState,
} from "react";
import type {
  ComponentType,
  CSSProperties,
  LazyExoticComponent,
  ReactNode,
} from "react";
import { experienceAttributes, inlineStyleVars } from "./attributes";
import { selectTemplate } from "./capabilities";
import { isStyleReady, loadStyle } from "./style-loader";
import type {
  Diagnostic,
  GeneratedRegistry,
  ModuleLoader,
  RegionProps,
  ResolvedExperience,
  ShellProps,
  TemplateProps,
} from "./types";

export type DiagnosticReporter = (d: Diagnostic) => void;
const consoleReporter: DiagnosticReporter = (d) =>
  console[d.level === "error" ? "error" : "warn"](
    `[experience] ${d.code}: ${d.message}`,
  );

interface ExperienceContextValue {
  experience: ResolvedExperience;
  registry: GeneratedRegistry;
  portalContainer: HTMLElement | null;
  report: DiagnosticReporter;
}

const ExperienceContext = createContext<ExperienceContextValue | null>(null);

export function useExperience(): ExperienceContextValue {
  const ctx = useContext(ExperienceContext);
  if (!ctx)
    throw new Error("useExperience must be used inside <ExperienceScope>.");
  return ctx;
}

export function usePortalContainer(): HTMLElement | undefined {
  return useContext(ExperienceContext)?.portalContainer ?? undefined;
}

export { experienceAttributes };

export interface ExperienceScopeProps {
  experience: ResolvedExperience;
  registry: GeneratedRegistry;
  children?: ReactNode;
  className?: string;
  /** Also set attributes on <html> so body-level portals inherit them (one surface per document only). */
  applyToDocument?: boolean;
  /** Where resolver/template diagnostics go (default: console). Send them to monitoring in production. */
  onDiagnostic?: DiagnosticReporter;
}

/**
 * The experience to paint. A style whose stylesheet loads on demand is shown once loaded; until then the
 * previously painted style and mode stay (everything else switches at once). A failed load keeps them too.
 */
function usePaintedExperience(
  experience: ResolvedExperience,
  registry: GeneratedRegistry,
  report: DiagnosticReporter,
): ResolvedExperience {
  const [painted, setPainted] = useState(experience);
  const ready = isStyleReady(registry, experience.style.id);
  useEffect(() => {
    if (ready) return;
    let live = true;
    loadStyle(registry, experience.style.id).then(
      () => live && setPainted(experience),
      (e: unknown) =>
        report({
          level: "error",
          code: "style-css",
          message: `Stylesheet of style "${experience.style.id}" failed to load: ${String(e)}`,
        }),
    );
    return () => {
      live = false;
    };
  }, [experience, registry, ready, report]);
  // Memoized so effects keyed on the painted experience do not re-run on every render while loading.
  return useMemo(
    () =>
      ready
        ? experience
        : { ...experience, style: painted.style, mode: painted.mode },
    [ready, experience, painted],
  );
}

export function ExperienceScope({
  experience: requested,
  registry,
  children,
  className,
  applyToDocument,
  onDiagnostic = consoleReporter,
}: ExperienceScopeProps) {
  const [portalContainer, setPortalContainer] = useState<HTMLElement | null>(
    null,
  );
  const experience = usePaintedExperience(requested, registry, onDiagnostic);
  const attrs = experienceAttributes(experience);
  const vars = inlineStyleVars(experience, registry) as
    CSSProperties | undefined;

  useEffect(() => {
    if (!applyToDocument) return;
    const el = document.documentElement;
    const entries = Object.entries(attrs);
    const previous = entries.map(([k]) => [k, el.getAttribute(k)] as const);
    const previousScheme = el.style.colorScheme;
    for (const [k, v] of entries) el.setAttribute(k, v);
    el.style.colorScheme = experience.mode;
    if (vars)
      for (const [k, v] of Object.entries(vars))
        el.style.setProperty(k, String(v));
    return () => {
      for (const [k, v] of previous) {
        if (v === null) el.removeAttribute(k);
        else el.setAttribute(k, v);
      }
      if (vars) for (const k of Object.keys(vars)) el.style.removeProperty(k);
      el.style.colorScheme = previousScheme;
    };
    // attrs/vars are derived from experience
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [applyToDocument, experience]);

  useEffect(() => {
    for (const d of requested.diagnostics) onDiagnostic(d);
  }, [requested, onDiagnostic]);

  const value = useMemo(
    () => ({ experience, registry, portalContainer, report: onDiagnostic }),
    [experience, registry, portalContainer, onDiagnostic],
  );
  return (
    <ExperienceContext.Provider value={value}>
      <div
        {...attrs}
        className={className}
        style={{ ...vars, colorScheme: experience.mode }}
      >
        {children}
        <div data-experience-portal="" ref={setPortalContainer} />
      </div>
    </ExperienceContext.Provider>
  );
}

// One lazy component per loader, so switching packs does not re-create components on every render.
const lazyCache = new WeakMap<
  object,
  LazyExoticComponent<ComponentType<any>>
>();
function lazyFor<P>(
  loader: ModuleLoader<P>,
): LazyExoticComponent<ComponentType<P>> {
  let c = lazyCache.get(loader);
  if (!c) lazyCache.set(loader, (c = lazy(loader)));
  return c as LazyExoticComponent<ComponentType<P>>;
}

export interface ExperiencePageProps<M> {
  pageKind: string;
  model: M;
  /** Presentation requirements derived by the page adapter from domain capabilities. */
  required?: ReadonlySet<string>;
  fallback?: ReactNode;
  /** Rendered when no registered template can present the required information. */
  blocked?: (missing: string[]) => ReactNode;
}

export function ExperiencePage<M>({
  pageKind,
  model,
  required,
  fallback = null,
  blocked,
}: ExperiencePageProps<M>) {
  const { experience, registry, report } = useExperience();
  const requiredKey = required ? [...required].sort().join("|") : "";
  const choice = useMemo(
    () => selectTemplate(registry, experience.pack, pageKind, required),
    // requiredKey stands in for the Set's contents
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [registry, experience.pack, pageKind, requiredKey],
  );

  useEffect(() => {
    for (const d of choice.diagnostics) report(d);
  }, [choice, report]);

  if (!choice.ok) {
    return (
      <>
        {blocked ? (
          blocked(choice.missing)
        ) : (
          <div role="alert" data-experience-blocked={pageKind}>
            This page cannot be displayed with the current design. Missing:{" "}
            {choice.missing.join(", ")}.
          </div>
        )}
      </>
    );
  }
  const Template = lazyFor<TemplateProps<string, M>>(choice.template.load);
  const Shell = experience.pack.shell
    ? lazyFor<ShellProps>(experience.pack.shell)
    : null;
  const page = <Template pageKind={pageKind} model={model} />;
  return (
    <Suspense fallback={fallback}>
      {Shell ? <Shell>{page}</Shell> : page}
    </Suspense>
  );
}

export interface ExperienceRegionProps<M> {
  /** Region id from the host contract. */
  region: string;
  model: M;
  fallback?: ReactNode;
}

/**
 * Renders the selected variant of a region (resolved per surface, independently of the pack). Every variant
 * receives the same model, so swapping one never changes data or behavior. The wrapper carries
 * [data-region][data-variant], the scope that variant stylesheets must use.
 */
export function ExperienceRegion<M>({
  region,
  model,
  fallback = null,
}: ExperienceRegionProps<M>) {
  const { experience, registry, report } = useExperience();
  const def = registry.regions?.[region];
  if (!def)
    throw new Error(
      `Region "${region}" is not in the registry: define it in experience.contract.json and regenerate.`,
    );
  const chosen = experience.regions[region] ?? def.default;
  const entry = def.variants[chosen] ?? def.variants[def.default];
  useEffect(() => {
    if (entry.id !== chosen)
      report({
        level: "warn",
        code: "region-unknown",
        message: `Region "${region}" has no variant "${chosen}"; using "${entry.id}".`,
      });
  }, [entry.id, chosen, region, report]);
  if (!entry.load) return null;
  const Variant = lazyFor<RegionProps<M>>(entry.load);
  return (
    <div data-region={region} data-variant={entry.id}>
      <Suspense fallback={fallback}>
        {/* The module-level lazyFor cache keeps the component identity stable. */}
        {/* eslint-disable-next-line react/static-components */}
        <Variant region={region} model={model} />
      </Suspense>
    </div>
  );
}
