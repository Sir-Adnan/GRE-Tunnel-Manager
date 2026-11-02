import { Login } from "@/features/Login";
import {
  lazy,
  Suspense,
  useCallback,
  useEffect,
  useMemo,
  useState,
} from "react";
import { Loader2 } from "lucide-react";
import { toast } from "sonner";
import { Toaster } from "@/components/ui/sonner";
import { PanelHeader } from "@/components/PanelHeader";
import { PanelFooter } from "@/components/PanelFooter";
import { CommandPalette } from "@/components/CommandPalette";
import { usePanelRoute } from "@/lib/use-panel-route";
import { ConnectionWorkspace } from "@/features/connections/ConnectionWorkspace";
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
import { Components, Settings } from "@/features/Settings";
import { usePanelCommands } from "@/features/commands";
import type { Connection } from "@/lib/api";
import { LocaleContext, translate } from "@/lib/i18n";
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
const Backups = lazy(() =>
  import("@/features/backups/Backups").then((module) => ({
    default: module.Backups,
  })),
);

const styleIds = Object.keys(registry.styles);
type FormState = { engine: string; engines?: string[]; original?: Connection };

function usePreferences() {
  const [preferences, setPreferences] = useState(() =>
    loadPreferences(globalThis.localStorage, styleIds),
  );
  useEffect(() => {
    savePreferences(globalThis.localStorage, preferences);
  }, [preferences]);
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
    : ["settings", "components", "traffic"].includes(page)
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
  const { page, navigate } = usePanelRoute();
  const [form, setForm] = useState<FormState>();
  const [palette, setPalette] = useState(false);
  const openPalette = useCallback(() => setPalette(true), []);
  useCommandShortcut(openPalette, authenticated);
  const add = useCallback(
    (engine = "haproxy", engines?: string[]) => setForm({ engine, engines }),
    [],
  );
  const edit = (original: Connection) =>
    setForm({ engine: original.engine, original });
  const refreshPage = useCallback(
    () =>
      page === "nodes"
        ? window.dispatchEvent(new Event("gtm:nodes-refresh"))
        : void refresh().catch((error) => toast.error(String(error))),
    [page, refresh],
  );
  const commands = usePanelCommands({
    t,
    inventory,
    preferences,
    setPreferences,
    navigate,
    add,
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
            />
            <main className="page-container" id="main">
              {session.demo && (
                <Alert className="demo-banner mb-5">
                  <AlertDescription>{t("demo")}</AlertDescription>
                </Alert>
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
                        ) : page === "components" ? (
                          <Components inventory={inventory} run={run} />
                        ) : page === "backups" ? (
                          <Backups inventory={inventory} refreshed={refresh} />
                        ) : (
                          <Settings
                            preferences={preferences}
                            setPreferences={setPreferences}
                            logout={() =>
                              void logout().catch((error) =>
                                toast.error(String(error)),
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
          <MobileNavigation page={page} navigate={navigate} />
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
              onClose={() => setForm(undefined)}
              onSubmit={run}
            />
          </Suspense>
        )}
        <Dialog
          open={Boolean(operations.output)}
          onOpenChange={(open) => !open && operations.closeOutput()}
        >
          <DialogContent closeLabel={t("close")} className="sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>{operations.output?.title}</DialogTitle>
              <DialogDescription>{t("reviewDesc")}</DialogDescription>
            </DialogHeader>
            <pre className="code-block max-h-[60dvh] overflow-auto" dir="ltr">
              {operations.output?.text}
            </pre>
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
