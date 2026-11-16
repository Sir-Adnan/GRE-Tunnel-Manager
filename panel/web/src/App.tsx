import { Login } from "@/features/Login";
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useLayoutEffect,
  useMemo,
  useRef,
  useState,
} from "react";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Toaster } from "@/components/ui/sonner";
import { PanelHeader } from "@/components/PanelHeader";
import { PanelFooter } from "@/components/PanelFooter";
import { CommandPalette } from "@/components/CommandPalette";
import { usePanelRoute } from "@/lib/use-panel-route";
import { duplicatePorts } from "@/lib/ports";
import { SafeChangeBanner } from "@/features/connections/SafeChangeBanner";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { SidebarProvider, SidebarInset } from "@/components/ui/sidebar";
import { MobileNavigation } from "@/components/MobileNavigation";
import { PanelSidebar } from "@/components/PanelSidebar";
import { Overview } from "@/features/Overview";
import { UpdateResultNotice } from "@/features/settings/Updates";
import { Components, Settings } from "@/features/Settings";
import { usePanelCommands } from "@/features/commands";
import type { Connection } from "@/lib/api";
import { createdConnection } from "@/features/check/model";
import type { TemplateID } from "@/lib/templates";
import { ErrorExplain } from "@/components/ErrorExplain";
import { errorKeys } from "@/lib/error-help";
import { errorMessage, LocaleContext, translate } from "@/lib/i18n";
import {
  defaultPreferences,
  loadPreferences,
  savePreferences,
} from "@/lib/preferences";
import { useSession } from "@/lib/use-session";
import { useInventory } from "@/lib/use-inventory";
import { useOperations } from "@/lib/use-operations";
import type { Page } from "@/lib/navigation";
import { ExperiencePage, ExperienceScope } from "@/experience/ExperienceScope";
import { resolveExperience } from "@/experience/resolve";
import { registry } from "@/experience/registry.generated";
const ConnectionForm = lazy(() =>
  import("@/features/connections/ConnectionForm").then((module) => ({
    default: module.ConnectionForm,
  })),
);
const ConnectionWorkspace = lazy(() =>
  import("@/features/connections/ConnectionWorkspace").then((m) => ({
    default: m.ConnectionWorkspace,
  })),
);
const Resources = lazy(() =>
  import("@/features/Resources").then((module) => ({
    default: module.Resources,
  })),
);
const Traffic = lazy(() =>
  import("@/features/Traffic").then((module) => ({ default: module.Traffic })),
);
const Nodes = lazy(() =>
  import("@/features/nodes/Nodes").then((module) => ({
    default: module.Nodes,
  })),
);
const Health = lazy(() =>
  import("@/features/Health").then((module) => ({ default: module.Health })),
);
const Maintenance = lazy(() =>
  import("@/features/Maintenance").then((module) => ({
    default: module.Maintenance,
  })),
);
const Optimize = lazy(() =>
  import("@/features/Optimize").then((module) => ({
    default: module.Optimize,
  })),
);
const Firewall = lazy(() =>
  import("@/features/firewall/Firewall").then((m) => ({ default: m.Firewall })),
);
const Addresses = lazy(() =>
  import("@/features/addresses/Addresses").then((m) => ({
    default: m.Addresses,
  })),
);
const History = lazy(() =>
  import("@/features/history/History").then((m) => ({ default: m.History })),
);
const Backups = lazy(() =>
  import("@/features/backups/Backups").then((module) => ({
    default: module.Backups,
  })),
);

const styleIds = Object.keys(registry.styles);
type FormState = {
  engine: string;
  engines?: string[];
  original?: Connection;
  copy?: Connection;
  template?: TemplateID;
};

function usePreferences() {
  const [preferences, setPreferences] = useState(() =>
    loadPreferences(globalThis.localStorage, styleIds),
  );
  useEffect(() => {
    savePreferences(globalThis.localStorage, preferences);
  }, [preferences]);
  // On the root, beside the style attributes, so dialogs and other portals follow it too.
  useEffect(() => {
    document.documentElement.dataset.density = preferences.density;
  }, [preferences.density]);
  // Screen readers, hyphenation, typography rules and portals read the language
  // from the root; set before paint so an English page never flashes RTL.
  useLayoutEffect(() => {
    const root = document.documentElement;
    root.lang = preferences.locale;
    root.dir = preferences.locale === "fa" ? "rtl" : "ltr";
  }, [preferences.locale]);
  return [preferences, setPreferences] as const;
}

function useSystemDark() {
  const [dark, setDark] = useState(
    () => matchMedia("(prefers-color-scheme: dark)").matches,
  );
  useEffect(() => {
    const query = matchMedia("(prefers-color-scheme: dark)");
    const changed = () => setDark(query.matches);
    query.addEventListener("change", changed);
    return () => query.removeEventListener("change", changed);
  }, []);
  return dark;
}

/** Ctrl/⌘+K anywhere opens the command palette. */
function useCommandShortcut(open: () => void, enabled: boolean) {
  useEffect(() => {
    if (!enabled) return;
    const keys = (event: KeyboardEvent) => {
      if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === "k") {
        event.preventDefault();
        open();
      }
    };
    window.addEventListener("keydown", keys);
    return () => window.removeEventListener("keydown", keys);
  }, [open, enabled]);
}

const lazyFallback = <Skeleton className="h-60 w-full" />;

function PageSkeleton() {
  return (
    <div className="flex flex-col gap-6" aria-busy>
      <Skeleton className="h-10 w-64" />
      <div className="stats-grid">
        {[0, 1, 2, 3].map((id) => (
          <Skeleton key={id} className="h-28" />
        ))}
      </div>
      <Skeleton className="h-80 w-full" />
    </div>
  );
}

function pageKind(page: Page) {
  return page === "overview"
    ? "dashboard"
    : [
          "settings",
          "components",
          "traffic",
          "maintenance",
          "optimize",
          "firewall",
          "addresses",
        ].includes(page)
      ? "settings"
      : "list";
}

export default function App() {
  const [preferences, setPreferences] = usePreferences();
  const systemDark = useSystemDark();
  const t = useCallback(
    (key: string) => translate(preferences.locale, key),
    [preferences.locale],
  );
  const { session, setSession, error: sessionError, logout } = useSession();
  const authenticated = Boolean(session?.authenticated);
  const operations = useOperations(t);
  const {
    inventory,
    error: inventoryError,
    refresh,
  } = useInventory({
    authenticated,
    autoRefresh: preferences.refresh,
    paused: operations.busy,
  });
  const runOperation = operations.run;
  const run = useCallback(
    (request: unknown) => runOperation(request, refresh),
    [runOperation, refresh],
  );
  const { page, params, navigate } = usePanelRoute();
  const [form, setForm] = useState<FormState>();
  // Forms that explain their own failed save: the connection editor and the
  // two-server wizard (?wizard=gre on Connections).
  const explainsFailure =
    Boolean(form) || (page === "connections" && params.get("wizard") === "gre");
  // A saved connection opens its Check tab once the refreshed inventory has
  // it; the save may resolve before or after React commits that inventory.
  const savedCheck = useRef<{ known: string[] }>(undefined);
  const latestInventory = useRef(inventory);
  const openCheck = useCallback(
    (id: string) =>
      navigate("connections", { connection: id, detail: "check", saved: "1" }),
    [navigate],
  );
  useEffect(() => {
    latestInventory.current = inventory;
    const saved = savedCheck.current;
    if (!saved || !inventory) return;
    const id = createdConnection(saved.known, inventory.connections);
    if (!id) return;
    savedCheck.current = undefined;
    openCheck(id);
  }, [inventory, openCheck]);
  const [palette, setPalette] = useState(false);
  const openPalette = useCallback(() => setPalette(true), []);
  useCommandShortcut(openPalette, authenticated);
  const add = useCallback(
    (engine = "haproxy", engines?: string[], template?: TemplateID) =>
      setForm({ engine, engines, template }),
    [],
  );
  const edit = useCallback(
    (original: Connection) => setForm({ engine: original.engine, original }),
    [],
  );
  // Duplicate: the same settings on the next free port (or range).
  const duplicate = useCallback(
    (source: Connection) =>
      setForm({
        engine: source.engine,
        copy: {
          ...source,
          name: source.name ? `${source.name.slice(0, 34)} copy` : "",
          ports: duplicatePorts(
            source.ports,
            latestInventory.current?.connections.map((c) => c.ports) ?? [],
          ),
          port_mode: source.ports.includes("-") ? "same" : "",
        },
      }),
    [],
  );
  const refreshPage = useCallback(
    () =>
      page === "nodes"
        ? window.dispatchEvent(new Event("gtm:nodes-refresh"))
        : void refresh().catch((error) => toast.error(errorMessage(error))),
    [page, refresh],
  );
  const commands = usePanelCommands({
    t,
    inventory,
    preferences,
    setPreferences,
    navigate,
    add,
    edit,
    duplicate,
    run,
    refresh: refreshPage,
  });
  const experience = useMemo(
    () =>
      resolveExperience({
        registry,
        surface: "admin",
        site: {
          styleId: defaultPreferences.style,
          mode: defaultPreferences.mode,
        },
        user: { styleId: preferences.style, mode: preferences.mode },
        userMay: { style: true, mode: true },
        locale: preferences.locale,
        systemPrefersDark: systemDark,
      }),
    [preferences, systemDark],
  );

  let content;
  if (!session)
    content = (
      <div className="grid min-h-dvh place-items-center p-6">
        {sessionError ? (
          <Alert>
            <AlertDescription>{sessionError}</AlertDescription>
          </Alert>
        ) : (
          <Loader2 className="size-6 animate-spin" aria-label="Loading" />
        )}
      </div>
    );
  else if (!authenticated)
    content = (
      <Login
        t={t}
        demo={session.demo}
        setSession={setSession}
        preferences={preferences}
        setPreferences={setPreferences}
      />
    );
  else
    content = (
      <div className="app-shell">
        <SidebarProvider>
          <PanelSidebar
            page={page}
            inventory={inventory}
            navigate={navigate}
            openPalette={openPalette}
          />
          <SidebarInset className="min-w-0">
            <PanelHeader
              page={page}
              inventory={inventory}
              preferences={preferences}
              setPreferences={setPreferences}
              busy={operations.busy}
              refresh={refreshPage}
              openPalette={openPalette}
              navigate={navigate}
            />
            <main className="page-container" id="main">
              {session.demo && (
                <Alert className="demo-banner mb-5">
                  <AlertDescription>{t("demo")}</AlertDescription>
                </Alert>
              )}
              {inventory && (
                <SafeChangeBanner
                  run={run}
                  refreshKey={String(
                    inventory.connections.reduce(
                      (h, c) =>
                        (h * 31 +
                          c.revision.charCodeAt(0) +
                          c.revision.charCodeAt(9)) %
                        1e9,
                      inventory.connections.length,
                    ),
                  )}
                />
              )}
              {inventoryError && (
                <Alert className="mb-5" variant="destructive">
                  <AlertDescription>{inventoryError}</AlertDescription>
                </Alert>
              )}
              {operations.busy && (
                <div className="operation-progress" role="status">
                  <Loader2 className="size-4 animate-spin" />
                  {t("working")}
                  <span className="text-xs opacity-70">
                    {operations.job?.action}
                  </span>
                </div>
              )}
              {page === "nodes" ? (
                <Suspense fallback={lazyFallback}>
                  <Nodes />
                </Suspense>
              ) : !inventory ? (
                <PageSkeleton />
              ) : (
                <ExperiencePage
                  key={page}
                  pageKind={pageKind(page)}
                  model={{
                    content: (
                      <Suspense fallback={lazyFallback}>
                        {page === "overview" ? (
                          <Overview
                            inventory={inventory}
                            add={() => add()}
                            edit={edit}
                            navigate={navigate}
                          />
                        ) : page === "connections" ? (
                          <ConnectionWorkspace
                            inventory={inventory}
                            add={add}
                            edit={edit}
                            duplicate={duplicate}
                            run={run}
                          />
                        ) : page === "gre" || page === "reverse" ? (
                          <Resources
                            inventory={inventory}
                            engine={page}
                            run={run}
                          />
                        ) : page === "traffic" ? (
                          <Traffic inventory={inventory} run={run} />
                        ) : page === "health" ? (
                          <Health inventory={inventory} run={run} />
                        ) : page === "maintenance" ? (
                          <Maintenance inventory={inventory} run={run} />
                        ) : page === "optimize" ? (
                          <Optimize inventory={inventory} run={run} />
                        ) : page === "firewall" ? (
                          <Firewall inventory={inventory} run={run} />
                        ) : page === "addresses" ? (
                          <Addresses refresh={refresh} />
                        ) : page === "components" ? (
                          <Components inventory={inventory} run={run} />
                        ) : page === "history" ? (
                          <History run={run} />
                        ) : page === "backups" ? (
                          <Backups
                            inventory={inventory}
                            refreshed={refresh}
                            run={run}
                          />
                        ) : (
                          <Settings
                            run={run}
                            preferences={preferences}
                            setPreferences={setPreferences}
                            logout={() =>
                              void logout().catch((error) =>
                                toast.error(errorMessage(error)),
                              )
                            }
                          />
                        )}
                      </Suspense>
                    ),
                  }}
                />
              )}
            </main>
            <PanelFooter inventory={inventory} />
          </SidebarInset>
          <MobileNavigation
            page={page}
            navigate={navigate}
            inventory={inventory}
            add={add}
            openPalette={openPalette}
            switchLocale={() =>
              setPreferences({
                ...preferences,
                locale: preferences.locale === "fa" ? "en" : "fa",
              })
            }
            refresh={refreshPage}
          />
        </SidebarProvider>
        <CommandPalette
          open={palette}
          onOpenChange={setPalette}
          commands={commands}
        />
        {form && inventory && (
          <Suspense
            fallback={
              <div className="operation-progress" role="status">
                {t("working")}
              </div>
            }
          >
            <ConnectionForm
              inventory={inventory}
              engines={form.original ? undefined : form.engines}
              engine={form.engine}
              original={form.original}
              copy={form.copy}
              template={form.template}
              onClose={() => {
                setForm(undefined);
                if (operations.output?.error) operations.closeOutput();
              }}
              onSubmit={run}
              onSaved={({ id, known }) => {
                const created =
                  id ??
                  createdConnection(
                    known,
                    latestInventory.current?.connections ?? [],
                  );
                if (created) openCheck(created);
                else savedCheck.current = { known };
              }}
            />
          </Suspense>
        )}
        <Dialog
          open={
            Boolean(operations.output) &&
            !(operations.output?.error && explainsFailure)
          }
          onOpenChange={(open) => !open && operations.closeOutput()}
        >
          <DialogContent closeLabel={t("close")} className="sm:max-w-2xl">
            {operations.output?.error ? (
              <>
                <DialogHeader>
                  <DialogTitle>
                    {t(errorKeys(operations.output.text).title)}
                  </DialogTitle>
                  <DialogDescription>{t("error")}</DialogDescription>
                </DialogHeader>
                <ErrorExplain
                  error={operations.output.text}
                  showTitle={false}
                  onNavigate={() => {
                    operations.closeOutput();
                    setForm(undefined);
                  }}
                />
              </>
            ) : (
              <>
                <DialogHeader>
                  <DialogTitle>{operations.output?.title}</DialogTitle>
                  <DialogDescription>{t("reviewDesc")}</DialogDescription>
                </DialogHeader>
                <pre
                  className="code-block max-h-[60dvh] overflow-auto"
                  dir="ltr"
                >
                  {operations.output?.text}
                </pre>
              </>
            )}
          </DialogContent>
        </Dialog>
      </div>
    );
  return (
    <LocaleContext.Provider value={preferences.locale}>
      <ExperienceScope
        registry={registry}
        experience={experience}
        applyToDocument
      >
        {content}
        <UpdateResultNotice version={inventory?.version} />
        <Toaster
          theme={experience.mode === "light" ? "light" : "dark"}
          dir={preferences.locale === "fa" ? "rtl" : "ltr"}
          position="bottom-center"
          closeButton
          offset={24}
          mobileOffset={{ bottom: 96, left: 16, right: 16 }}
        />
      </ExperienceScope>
    </LocaleContext.Provider>
  );
}
