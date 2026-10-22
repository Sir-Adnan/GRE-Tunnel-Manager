import { Login } from "@/features/Login";
import { useCallback, useEffect, useMemo, useState } from "react";
import {
  Activity,
  ArrowRight,
  Check,
  ChevronRight,
  Gauge,
  Globe2,
  Layers3,
  Loader2,
  Menu,
  Network,
  Plus,
  RefreshCw,
  Server,
  Settings2,
  ShieldCheck,
  Workflow,
  X,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Sheet,
  SheetContent,
  SheetHeader,
  SheetTitle,
} from "@/components/ui/sheet";
import { Skeleton } from "@/components/ui/skeleton";
import { Separator } from "@/components/ui/separator";
import { Logo, Address, PageTitle } from "@/components/shared";
import { ConnectionForm } from "@/features/connections/ConnectionForm";
import { ConnectionTable } from "@/features/connections/ConnectionTable";
import { Overview } from "@/features/Overview";
import { Resources } from "@/features/Resources";
import { Traffic } from "@/features/Traffic";
import { Components, Settings } from "@/features/Settings";
import type { Preferences } from "@/features/Settings";
import { api, operate } from "@/lib/api";
import type { Connection, Inventory, Job, Session } from "@/lib/api";
import { LocaleContext, translate } from "@/lib/i18n";
import { ExperiencePage, ExperienceScope } from "@/experience/ExperienceScope";
import { resolveExperience } from "@/experience/resolve";
import { registry } from "@/experience/registry.generated";

const defaults: Preferences = {
  locale: "fa",
  style: "nettinx",
  mode: "dark",
  refresh: false,
};
function savedPreferences(): Preferences {
  try {
    const value = JSON.parse(
      localStorage.getItem("gtm.preferences.v1") || "{}",
    );
    return {
      locale: value.locale === "en" ? "en" : "fa",
      style: Object.hasOwn(registry.styles, value.style)
        ? value.style
        : defaults.style,
      mode: ["light", "dark", "system"].includes(value.mode)
        ? value.mode
        : defaults.mode,
      refresh: value.refresh === true,
    };
  } catch {
    return defaults;
  }
}
const navGroups = [
  {
    title: "workspace",
    items: [
      { id: "overview", icon: Gauge },
      { id: "connections", icon: Layers3 },
      { id: "traffic", icon: Activity },
    ],
  },
  {
    title: "infrastructure",
    items: [
      { id: "gre", icon: Network },
      { id: "forwarding", icon: ArrowRight },
      { id: "haproxy", icon: Workflow, label: "HAProxy" },
      { id: "realm", icon: Network, label: "Realm" },
      { id: "reverse", icon: ArrowRight },
    ],
  },
  {
    title: "preferences",
    items: [
      { id: "components", icon: Server },
      { id: "settings", icon: Settings2 },
    ],
  },
];

export default function App() {
  const [preferences, setPreferences] = useState(savedPreferences);
  const [session, setSession] = useState<Session>();
  const [sessionError, setSessionError] = useState("");
  const [inventory, setInventory] = useState<Inventory>();
  const [page, setPage] = useState("overview");
  const [mobileNav, setMobileNav] = useState(false);
  const [form, setForm] = useState<{ engine: string; original?: Connection }>();
  const [toast, setToast] = useState("");
  const [job, setJob] = useState<Job>();
  const [output, setOutput] = useState<{ title: string; text: string }>();
  const [systemDark, setSystemDark] = useState(
    () => matchMedia("(prefers-color-scheme: dark)").matches,
  );
  const t = useCallback(
    (key: string) => translate(preferences.locale, key),
    [preferences.locale],
  );
  const experience = useMemo(
    () =>
      resolveExperience({
        registry,
        surface: "admin",
        site: { styleId: "nettinx", mode: "dark" },
        user: { styleId: preferences.style, mode: preferences.mode },
        userMay: { style: true, mode: true },
        locale: preferences.locale,
        systemPrefersDark: systemDark,
      }),
    [preferences, systemDark],
  );
  const refresh = useCallback(async () => {
    setInventory(await api<Inventory>("inventory"));
  }, []);
  useEffect(() => {
    api<Session>("session")
      .then(setSession)
      .catch((error) => setSessionError(String(error)));
  }, []);
  useEffect(() => {
    const expired = () => {
      setSession({
        authenticated: false,
        session: { csrf: "", username: "", expires: "" },
        demo: false,
      });
      setInventory(undefined);
    };
    window.addEventListener("gtm:unauthorized", expired);
    return () => window.removeEventListener("gtm:unauthorized", expired);
  }, []);
  useEffect(() => {
    localStorage.setItem("gtm.preferences.v1", JSON.stringify(preferences));
  }, [preferences]);
  useEffect(() => {
    const query = matchMedia("(prefers-color-scheme: dark)");
    const changed = () => setSystemDark(query.matches);
    query.addEventListener("change", changed);
    return () => query.removeEventListener("change", changed);
  }, []);
  useEffect(() => {
    if (!session?.authenticated) return;
    let alive = true;
    api<Inventory>("inventory")
      .then((value) => alive && setInventory(value))
      .catch((error) => alive && setSessionError(String(error)));
    return () => {
      alive = false;
    };
  }, [session?.authenticated]);
  useEffect(() => {
    if (!session?.authenticated || !preferences.refresh) return;
    const timer = window.setInterval(() => {
      if (!document.hidden && job?.state !== "running")
        refresh().catch((error) => setToast(String(error)));
    }, 30000);
    return () => clearInterval(timer);
  }, [session?.authenticated, preferences.refresh, refresh, job?.state]);
  useEffect(() => {
    if (!toast) return;
    const timer = setTimeout(() => setToast(""), 4500);
    return () => clearTimeout(timer);
  }, [toast]);
  function navigate(next: string) {
    setPage(next);
    setMobileNav(false);
    window.scrollTo({ top: 0, behavior: "instant" });
  }
  const add = (
    engine = ["haproxy", "realm"].includes(page)
      ? page
      : page === "forwarding"
        ? "nftables"
        : "haproxy",
  ) => setForm({ engine });
  const edit = (original: Connection) =>
    setForm({ engine: original.engine, original });
  async function run(request: unknown): Promise<void> {
    try {
      const completed = await operate(request, setJob);
      await refresh();
      setToast(t("completed"));
      const operation = (request as { action: string }).action;
      if (["logs", "plan", "doctor", "reverse-create"].includes(operation))
        setOutput({
          title: t(
            operation === "logs"
              ? "logs"
              : operation === "reverse-create"
                ? "completed"
                : "review",
          ),
          text:
            typeof completed.result === "string"
              ? completed.result
              : JSON.stringify(completed.result, null, 2),
        });
    } catch (error) {
      setOutput({
        title: t("error"),
        text: error instanceof Error ? error.message : String(error),
      });
      throw error;
    }
  }
  async function logout() {
    await api("logout", {});
    setSession({
      authenticated: false,
      session: { csrf: "", username: "", expires: "" },
      demo: false,
    });
    setInventory(undefined);
  }
  const navigation = (
    <nav className="flex flex-col gap-7" aria-label={t("workspace")}>
      {navGroups.map((group) => (
        <div key={group.title} className="flex flex-col gap-1">
          <div className="nav-group-title">{t(group.title)}</div>
          {group.items.map((item) => (
            <button
              key={item.id}
              className="nav-item"
              data-active={page === item.id}
              onClick={() => navigate(item.id)}
              aria-current={page === item.id ? "page" : undefined}
            >
              <item.icon className="size-4" />
              <span>{"label" in item ? item.label : t(item.id)}</span>
              {item.id === "connections" && inventory && (
                <span className="nav-count">
                  {inventory.connections.length}
                </span>
              )}
            </button>
          ))}
        </div>
      ))}
    </nav>
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
  else if (!session.authenticated)
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
        <aside className="desktop-sidebar">
          <div className="sidebar-brand">
            <Logo />
          </div>
          {navigation}
          <div className="sidebar-footer">
            <Separator />
            <div className="flex items-center gap-2.5 py-4">
              <span className="server-avatar">
                <Server className="size-4" />
              </span>
              <div className="min-w-0 flex-1">
                <p className="truncate text-xs font-medium" dir="ltr">
                  {inventory?.host.hostname || "Server"}
                </p>
                <p className="text-[10px] text-muted-foreground" dir="ltr">
                  v{inventory?.version || "1.3.0"} · HTTPS
                </p>
              </div>
              <ShieldCheck className="size-4 text-muted-foreground" />
            </div>
          </div>
        </aside>
        <div className="app-main">
          <header className="topbar">
            <div className="flex min-w-0 items-center gap-3">
              <Button
                variant="ghost"
                size="icon"
                className="lg:hidden"
                aria-label={t("workspace")}
                onClick={() => setMobileNav(true)}
              >
                <Menu />
              </Button>
              <span className="hidden text-sm text-muted-foreground sm:inline">
                Tunnel Manager
              </span>
              <ChevronRight className="hidden size-3.5 text-muted-foreground rtl:rotate-180 sm:block" />
              <span className="truncate text-sm font-medium">
                {page === "haproxy"
                  ? "HAProxy"
                  : page === "realm"
                    ? "Realm"
                    : t(page)}
              </span>
            </div>
            <div className="flex items-center gap-1.5">
              <span className="hidden md:block">
                {inventory?.host.addresses[0] && (
                  <Address notify={setToast}>
                    {inventory.host.addresses[0]}
                  </Address>
                )}
              </span>
              <Button
                variant="ghost"
                size="icon"
                aria-label={t("refresh")}
                disabled={job?.state === "running"}
                onClick={() =>
                  refresh().catch((error) => setToast(String(error)))
                }
              >
                <RefreshCw />
              </Button>
              <Button
                variant="ghost"
                size="sm"
                aria-label={t("language")}
                onClick={() =>
                  setPreferences({
                    ...preferences,
                    locale: preferences.locale === "fa" ? "en" : "fa",
                  })
                }
              >
                <Globe2 data-icon="inline-start" />
                {preferences.locale === "fa" ? "EN" : "فا"}
              </Button>
            </div>
          </header>
          <div className="page-container">
            {session.demo && (
              <Alert className="mb-5">
                <AlertDescription>{t("demo")}</AlertDescription>
              </Alert>
            )}
            {sessionError && (
              <Alert className="mb-5">
                <AlertDescription>{sessionError}</AlertDescription>
              </Alert>
            )}
            {job?.state === "running" && (
              <div className="operation-progress" role="status">
                <Loader2 className="size-4 animate-spin" />
                {t("working")}
                <span className="text-xs opacity-70">{job.action}</span>
              </div>
            )}
            {!inventory ? (
              <div className="flex flex-col gap-6">
                <Skeleton className="h-12 w-72" />
                <div className="stats-grid">
                  {[0, 1, 2, 3].map((id) => (
                    <Skeleton key={id} className="h-36" />
                  ))}
                </div>
                <Skeleton className="h-80 w-full" />
              </div>
            ) : (
              <ExperiencePage
                pageKind={
                  page === "overview"
                    ? "dashboard"
                    : ["settings", "components", "traffic"].includes(page)
                      ? "settings"
                      : "list"
                }
                model={{
                  content:
                    page === "overview" ? (
                      <Overview
                        inventory={inventory}
                        add={() => add()}
                        edit={edit}
                        navigate={navigate}
                        run={run}
                      />
                    ) : [
                        "connections",
                        "forwarding",
                        "haproxy",
                        "realm",
                      ].includes(page) ? (
                      <div className="page-stack">
                        <PageTitle
                          title={
                            page === "haproxy"
                              ? "HAProxy"
                              : page === "realm"
                                ? "Realm"
                                : t(page)
                          }
                          description={t("subtitle")}
                          action={
                            <Button onClick={() => add()}>
                              <Plus data-icon="inline-start" />
                              {t("newConnection")}
                            </Button>
                          }
                        />
                        <Card>
                          <CardHeader>
                            <CardTitle>{t("connections")}</CardTitle>
                            <CardDescription>
                              {page === "haproxy"
                                ? inventory.capabilities.find(
                                    (c) => c.id === "haproxy",
                                  )?.scope
                                : page === "realm"
                                  ? inventory.capabilities.find(
                                      (c) => c.id === "realm",
                                    )?.scope
                                  : t("emptyDesc")}
                            </CardDescription>
                          </CardHeader>
                          <CardContent>
                            <ConnectionTable
                              connections={inventory.connections.filter(
                                (c) =>
                                  page === "connections" ||
                                  (page === "forwarding"
                                    ? ["nftables", "iptables"].includes(
                                        c.engine,
                                      )
                                    : c.engine === page),
                              )}
                              onAdd={() => add()}
                              onEdit={edit}
                              run={run}
                            />
                          </CardContent>
                          <CardFooter>
                            <Button
                              variant="ghost"
                              onClick={() =>
                                void run({ action: "plan" }).catch(() => {})
                              }
                            >
                              {t("review")}
                              <ChevronRight
                                data-icon="inline-end"
                                className="rtl:rotate-180"
                              />
                            </Button>
                          </CardFooter>
                        </Card>
                      </div>
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
                    ) : (
                      <Settings
                        preferences={preferences}
                        setPreferences={setPreferences}
                        logout={() =>
                          void logout().catch((error) =>
                            setToast(String(error)),
                          )
                        }
                      />
                    ),
                }}
              />
            )}
          </div>
          <footer className="app-footer">
            <span>TUNNEL MANAGER</span>
            <span>
              {inventory?.host.hostname} · v{inventory?.version || "1.3.0"}
            </span>
          </footer>
        </div>
        <Sheet open={mobileNav} onOpenChange={setMobileNav}>
          <SheetContent
            closeLabel={t("close")}
            side={preferences.locale === "fa" ? "right" : "left"}
            className="w-72"
          >
            <SheetHeader>
              <SheetTitle>
                <Logo />
              </SheetTitle>
            </SheetHeader>
            <div className="px-4">{navigation}</div>
          </SheetContent>
        </Sheet>
        {form && inventory && (
          <ConnectionForm
            inventory={inventory}
            engine={form.engine}
            original={form.original}
            onClose={() => setForm(undefined)}
            onSubmit={run}
          />
        )}
        <Dialog
          open={Boolean(output)}
          onOpenChange={(open) => !open && setOutput(undefined)}
        >
          <DialogContent closeLabel={t("close")} className="sm:max-w-2xl">
            <DialogHeader>
              <DialogTitle>{output?.title}</DialogTitle>
              <DialogDescription>{t("reviewDesc")}</DialogDescription>
            </DialogHeader>
            <pre className="code-block max-h-[60dvh] overflow-auto" dir="ltr">
              {output?.text}
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
        {toast && (
          <div className="toast" role="status">
            <Check className="size-4" />
            <span>{toast}</span>
            <Button
              variant="ghost"
              size="icon-sm"
              aria-label={t("close")}
              onClick={() => setToast("")}
            >
              <X />
            </Button>
          </div>
        )}
      </ExperienceScope>
    </LocaleContext.Provider>
  );
}
