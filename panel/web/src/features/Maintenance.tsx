import { useContext, useMemo, useState } from "react";
import {
  CalendarClock,
  HeartPulse,
  Hourglass,
  ListChecks,
  Plus,
  ScrollText,
  Settings2,
  Timer,
  TriangleAlert,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {
  Empty,
  EmptyContent,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import { Switch } from "@/components/ui/switch";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Choice, PageTitle } from "@/components/shared";
import type { Inventory } from "@/lib/api";
import { LocaleContext, useT } from "@/lib/i18n";
import { usePanelRoute } from "@/lib/use-panel-route";
import { useMaintenanceView, useNow } from "@/features/operations/hooks";
import type {
  MaintenanceView,
  Owner,
  Plan,
  PlanView,
} from "@/features/operations/types";
import { duration, secondsUntil, stamp } from "@/features/health/format";
import { Confirm, type ConfirmRequest } from "./maintenance/Confirm";
import { HistoryTable } from "./maintenance/HistoryTable";
import { PlanCard } from "./maintenance/PlanCard";
import { PlanEditor } from "./maintenance/PlanEditor";

/** Zones offered by default; the current value is always included. */
const zones = [
  "Asia/Tehran",
  "UTC",
  "Europe/Istanbul",
  "Asia/Dubai",
  "Europe/Berlin",
  "Europe/Amsterdam",
  "Europe/London",
  "America/New_York",
];

function ownersOf(inventory: Inventory): Owner[] {
  return [
    ...inventory.connections
      .filter((c) => c.enabled)
      .map((c) => ({ id: c.id, name: c.name || c.id, engine: c.engine })),
    ...inventory.resources.map((r) => ({
      id: r.id,
      name: r.name || r.id,
      engine: r.engine,
    })),
  ];
}

function Pending({
  plans,
  timezone,
  cancel,
}: {
  plans: PlanView[];
  timezone: string;
  cancel: (plan: PlanView) => void;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const pending = plans.filter((p) => p.state.pending);
  const now = useNow(pending.length > 0);
  if (!pending.length) return null;
  return (
    <div className="flex flex-col gap-2" role="status" aria-live="polite">
      {pending.map((plan) => {
        const p = plan.state.pending!;
        const left = secondsUntil(p.run_at, now) ?? 0;
        const text =
          left > 0
            ? t("mxPendingNotice").replace("{d}", duration(left, locale))
            : p.deadline
              ? t("mxPendingQuiet").replace(
                  "{t}",
                  stamp(p.deadline, locale, timezone),
                )
              : t("mxPendingSoon");
        return (
          <Alert
            key={plan.id}
            className="pending-alert"
            data-action={plan.action}
          >
            {left > 0 ? <Timer /> : <Hourglass />}
            <AlertDescription className="flex flex-wrap items-center justify-between gap-3">
              <span>
                <bdi>{text.replace("{name}", plan.name)}</bdi>
              </span>
              <Button size="sm" variant="outline" onClick={() => cancel(plan)}>
                {t("mxCancelRun")}
              </Button>
            </AlertDescription>
          </Alert>
        );
      })}
    </div>
  );
}

function SettingsDialog({
  open,
  onOpenChange,
  view,
  save,
}: {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  view: MaintenanceView;
  save: (timezone: string) => Promise<void>;
}) {
  const t = useT();
  const [zone, setZone] = useState(view.settings.timezone);
  const [busy, setBusy] = useState(false);
  const choices = [...new Set([view.settings.timezone, ...zones])].map((z) => ({
    value: z,
    label: z,
  }));
  return (
    <Dialog
      open={open}
      onOpenChange={(next) => {
        if (next) setZone(view.settings.timezone);
        onOpenChange(next);
      }}
    >
      <DialogContent closeLabel={t("close")} className="sm:max-w-md">
        <DialogHeader>
          <DialogTitle>{t("mxSettings")}</DialogTitle>
          <DialogDescription>{t("mxTimezoneHelp")}</DialogDescription>
        </DialogHeader>
        <Choice
          id="mx-zone"
          label={t("mxTimezone")}
          value={zone}
          onChange={setZone}
          choices={choices}
        />
        <DialogFooter>
          <Button variant="outline" onClick={() => onOpenChange(false)}>
            {t("cancel")}
          </Button>
          <Button
            disabled={busy}
            onClick={() => {
              setBusy(true);
              save(zone)
                .then(() => onOpenChange(false))
                .catch(() => undefined)
                .finally(() => setBusy(false));
            }}
          >
            {t("save")}
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

export function Maintenance({
  inventory,
  run,
}: {
  inventory: Inventory;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { params, updateParams, navigate } = usePanelRoute();
  const { value: view, error, reload } = useMaintenanceView();
  const [editor, setEditor] = useState<{ key: number; plan?: Plan }>();
  const [confirm, setConfirm] = useState<ConfirmRequest>();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const owners = useMemo(() => ownersOf(inventory), [inventory]);
  const tab = params.get("tab") === "history" ? "history" : "plans";

  async function mutate(action: string, maintenance: Record<string, unknown>) {
    if (!view) return;
    setBusy(true);
    try {
      await run({
        action,
        maintenance: { revision: view.revision, ...maintenance },
      });
    } finally {
      await reload();
      setBusy(false);
    }
  }
  const quiet = (promise: Promise<void>) => void promise.catch(() => undefined);
  const savePlan = (plan: Plan) => mutate("maintenance-save", { plan });
  const open = (plan?: Plan) => setEditor({ key: Date.now(), plan });

  function runNow(plan: PlanView) {
    setConfirm({
      title: t("mxRunConfirmTitle"),
      body: plan.action === "reboot" ? t("mxRebootConfirm") : t("mxRunConfirm"),
      action: t("mxRunNow"),
      destructive: plan.action === "reboot" && !plan.dry_run,
      run: () => mutate("maintenance-run", { id: plan.id }),
    });
  }
  function remove(plan: PlanView) {
    setConfirm({
      title: t("mxDeletePlan"),
      body: t("mxDeleteConfirm"),
      action: t("delete"),
      destructive: true,
      run: () => mutate("maintenance-delete", { id: plan.id }),
    });
  }
  function strip(plan: PlanView): Plan {
    const { state: _state, ...rest } = plan;
    void _state;
    return rest;
  }

  const enabled = Boolean(view?.settings.enabled);
  return (
    <div className="page-stack">
      <PageTitle
        title={t("maintenance")}
        description={t("maintenanceIntro")}
        action={
          view && (
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSettingsOpen(true)}
              >
                <Settings2 data-icon="inline-start" />
                <bdi dir="ltr">{view.settings.timezone}</bdi>
              </Button>
              <label className="module-switch">
                <Switch
                  checked={enabled}
                  disabled={busy}
                  onCheckedChange={(next) =>
                    quiet(
                      mutate("maintenance-configure", {
                        settings: { ...view.settings, enabled: next },
                      }),
                    )
                  }
                />
                <span>{t("mxScheduler")}</span>
              </label>
              <Button size="sm" onClick={() => open()}>
                <Plus data-icon="inline-start" />
                {t("mxNewPlan")}
              </Button>
            </div>
          )
        }
      />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {!view ? (
        <Skeleton className="h-80 w-full" />
      ) : (
        <>
          <Pending
            plans={view.plans}
            timezone={view.settings.timezone}
            cancel={(plan) =>
              quiet(mutate("maintenance-cancel", { id: plan.id }))
            }
          />
          <div className="mx-strip">
            <span>
              <Timer className="size-4" />
              <bdi>
                {t("mxUptimeNow").replace(
                  "{d}",
                  duration(view.uptime_seconds, locale),
                )}
              </bdi>
            </span>
            <button type="button" onClick={() => navigate("health")}>
              <HeartPulse className="size-4" />
              {t("mxHealthLink").replace(
                "{s}",
                t(view.health_enabled ? "mxOn" : "mxOff"),
              )}
            </button>
          </div>
          {!enabled && view.plans.length > 0 && (
            <Alert>
              <TriangleAlert />
              <AlertDescription>{t("mxOffNote")}</AlertDescription>
            </Alert>
          )}
          <Tabs
            value={tab}
            onValueChange={(value) =>
              updateParams({ tab: value === "plans" ? "" : value })
            }
            dir={locale === "fa" ? "rtl" : "ltr"}
            className="gap-5"
          >
            <TabsList>
              <TabsTrigger value="plans">
                <ListChecks />
                {t("mxPlansTab")}
              </TabsTrigger>
              <TabsTrigger value="history">
                <ScrollText />
                {t("mxHistoryTab")}
              </TabsTrigger>
            </TabsList>
            <TabsContent value="plans">
              {view.plans.length === 0 ? (
                <Empty className="min-h-72 rounded-xl border bg-card">
                  <EmptyHeader>
                    <EmptyMedia variant="icon">
                      <CalendarClock />
                    </EmptyMedia>
                    <EmptyTitle>{t("mxEmptyTitle")}</EmptyTitle>
                    <EmptyDescription>{t("mxEmptyBody")}</EmptyDescription>
                  </EmptyHeader>
                  <EmptyContent>
                    <Button onClick={() => open()}>
                      <Plus data-icon="inline-start" />
                      {t("mxNewPlan")}
                    </Button>
                  </EmptyContent>
                </Empty>
              ) : (
                <div className="plan-grid">
                  {view.plans.map((plan) => (
                    <PlanCard
                      key={plan.id}
                      plan={plan}
                      owners={owners}
                      timezone={view.settings.timezone}
                      moduleEnabled={enabled}
                      busy={busy}
                      toggle={(next) =>
                        quiet(savePlan({ ...strip(plan), enabled: next }))
                      }
                      edit={() => open(strip(plan))}
                      duplicate={() =>
                        open({
                          ...strip(plan),
                          id: "",
                          name: t("mxCopy")
                            .replace("{name}", plan.name)
                            .slice(0, 60),
                          enabled: false,
                        })
                      }
                      remove={() => remove(plan)}
                      runNow={() => runNow(plan)}
                    />
                  ))}
                </div>
              )}
            </TabsContent>
            <TabsContent value="history">
              <HistoryTable
                history={view.history}
                timezone={view.settings.timezone}
              />
            </TabsContent>
          </Tabs>
          <SettingsDialog
            open={settingsOpen}
            onOpenChange={setSettingsOpen}
            view={view}
            save={(timezone) =>
              mutate("maintenance-configure", {
                settings: { ...view.settings, timezone },
              })
            }
          />
        </>
      )}
      {editor && view && (
        <PlanEditor
          key={editor.key}
          open
          initial={editor.plan}
          owners={owners}
          healthEnabled={view.health_enabled}
          conntrackCLI={view.conntrack_cli}
          onClose={() => setEditor(undefined)}
          save={savePlan}
        />
      )}
      <Confirm request={confirm} onClose={() => setConfirm(undefined)} />
    </div>
  );
}
