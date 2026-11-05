import { useContext, useState } from "react";
import {
  Activity,
  CircleAlert,
  FileChartColumn,
  HeartPulse,
  ListChecks,
  Server,
  Settings2,
  Timer,
  type LucideIcon,
} from "lucide-react";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
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
import { PageTitle } from "@/components/shared";
import { number } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { usePanelRoute } from "@/lib/use-panel-route";
import { cn } from "@/lib/utils";
import { useHealthView } from "@/features/operations/hooks";
import type { HealthSettings, HealthView } from "@/features/operations/types";
import { HealthSettingsDialog } from "./health/HealthSettingsDialog";
import { OutageList } from "./health/OutageList";
import { OwnerList } from "./health/OwnerList";
import { ServerPressure } from "./health/ServerPressure";
import { WeeklyReport } from "./health/WeeklyReport";
import { milliseconds, percent, uptimeTone } from "./health/format";

const tabs = ["status", "outages", "report", "server"] as const;

function Tile({
  icon: Icon,
  label,
  value,
  detail,
  tone,
}: {
  icon: LucideIcon;
  label: string;
  value: string;
  detail: string;
  tone?: "alert" | "ok";
}) {
  return (
    <div className={cn("kpi", tone && `is-${tone}`)}>
      <span className="kpi-label">
        <Icon className="size-4" />
        {label}
      </span>
      <span className="kpi-value">
        <bdi dir="ltr">{value}</bdi>
      </span>
      <span className="kpi-detail">
        <bdi>{detail}</bdi>
      </span>
    </div>
  );
}

function Summary({ view }: { view: HealthView }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const s = view.summary;
  const tone = uptimeTone(s.uptime_7d);
  return (
    <div className="kpi-grid">
      <Tile
        icon={HeartPulse}
        label={t("healthUptime7d")}
        value={percent(s.uptime_7d, locale)}
        detail={t("healthUptime24hDetail").replace(
          "{v}",
          percent(s.uptime_24h, locale),
        )}
        tone={tone === "ok" ? "ok" : tone === "none" ? undefined : "alert"}
      />
      <Tile
        icon={Activity}
        label={t("healthTunnelsUp")}
        value={`${number(s.up, locale)} / ${number(s.owners, locale)}`}
        detail={t("healthTunnelsDetail")
          .replace("{down}", number(s.down, locale))
          .replace("{degraded}", number(s.degraded, locale))}
        tone={s.down || s.degraded ? "alert" : s.owners ? "ok" : undefined}
      />
      <Tile
        icon={CircleAlert}
        label={t("healthOpenOutages")}
        value={number(s.open_outages, locale)}
        detail={s.open_outages ? t("healthOngoing") : t("healthOpenNone")}
        tone={s.open_outages ? "alert" : "ok"}
      />
      <Tile
        icon={Timer}
        label={t("healthLatency")}
        value={milliseconds(s.latency_ms, locale)}
        detail={t("healthLatencyDetail")}
      />
    </div>
  );
}

export function Health({ run }: { run: (request: unknown) => Promise<void> }) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { params, updateParams } = usePanelRoute();
  const { value: view, error, reload } = useHealthView();
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const tab = tabs.find((x) => x === params.get("tab")) ?? "status";
  async function configure(settings: HealthSettings) {
    if (!view) return;
    await run({
      action: "health-configure",
      health: { settings, revision: view.revision },
    });
    await reload();
  }
  function toggle(enabled: boolean) {
    if (!view) return;
    setBusy(true);
    configure({ ...view.settings, enabled })
      .catch(() => undefined)
      .finally(() => setBusy(false));
  }
  const enabled = Boolean(view?.settings.enabled);
  return (
    <div className="page-stack">
      <PageTitle
        title={t("health")}
        description={t("healthIntro")}
        action={
          view && (
            <div className="flex flex-wrap items-center gap-2">
              {enabled && (
                <Badge variant="outline" className="gap-1.5">
                  <span className="live-dot" aria-hidden />
                  {t("healthEvery").replace(
                    "{n}",
                    String(view.settings.interval),
                  )}
                </Badge>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => setSettingsOpen(true)}
              >
                <Settings2 data-icon="inline-start" />
                {t("settings")}
              </Button>
              <label className="module-switch">
                <Switch
                  checked={enabled}
                  disabled={busy}
                  onCheckedChange={toggle}
                />
                <span>{t("healthMonitoring")}</span>
              </label>
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
      ) : !enabled && !view.owners.length ? (
        <Empty className="min-h-72 rounded-xl border bg-card">
          <EmptyHeader>
            <EmptyMedia variant="icon">
              <HeartPulse />
            </EmptyMedia>
            <EmptyTitle>{t("healthOffTitle")}</EmptyTitle>
            <EmptyDescription>{t("healthOffBody")}</EmptyDescription>
          </EmptyHeader>
          <EmptyContent>
            <Button disabled={busy} onClick={() => toggle(true)}>
              {t("healthTurnOn")}
            </Button>
          </EmptyContent>
        </Empty>
      ) : (
        <>
          {!enabled && (
            <Alert>
              <CircleAlert />
              <AlertDescription>{t("healthOffBody")}</AlertDescription>
            </Alert>
          )}
          <Summary view={view} />
          <Tabs
            value={tab}
            onValueChange={(value) =>
              updateParams({ tab: value === "status" ? "" : value })
            }
            dir={locale === "fa" ? "rtl" : "ltr"}
            className="gap-5"
          >
            <TabsList className="max-w-full justify-start overflow-x-auto [scrollbar-width:none] [&>button]:shrink-0">
              <TabsTrigger value="status">
                <ListChecks />
                {t("healthStatusTab")}
              </TabsTrigger>
              <TabsTrigger value="outages">
                <CircleAlert />
                {t("healthOutagesTab")}
                {view.summary.open_outages > 0 && (
                  <span className="tab-count is-alert">
                    <bdi dir="ltr">{view.summary.open_outages}</bdi>
                  </span>
                )}
              </TabsTrigger>
              <TabsTrigger value="report">
                <FileChartColumn />
                {t("healthReportTab")}
              </TabsTrigger>
              <TabsTrigger value="server">
                <Server />
                {t("healthServerTab")}
              </TabsTrigger>
            </TabsList>
            <TabsContent value="status">
              {view.owners.length === 0 ? (
                <p className="rounded-lg border border-dashed p-6 text-center text-sm text-muted-foreground">
                  {enabled ? t("healthNoTargets") : t("healthWaiting")}
                </p>
              ) : (
                <OwnerList
                  owners={view.owners}
                  time={view.time}
                  timezone={view.timezone}
                />
              )}
            </TabsContent>
            <TabsContent value="outages">
              <OutageList
                outages={view.outages}
                time={view.time}
                timezone={view.timezone}
              />
            </TabsContent>
            <TabsContent value="report">
              <WeeklyReport />
            </TabsContent>
            <TabsContent value="server">
              <ServerPressure host={view.host} />
            </TabsContent>
          </Tabs>
        </>
      )}
      {view && (
        <HealthSettingsDialog
          open={settingsOpen}
          onOpenChange={setSettingsOpen}
          settings={view.settings}
          save={configure}
        />
      )}
    </div>
  );
}
