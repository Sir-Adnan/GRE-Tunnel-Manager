import { lazy, Suspense, useContext, useState, useEffect } from "react";
import {
  ArrowDownLeft,
  ArrowUpRight,
  Download,
  SlidersHorizontal,
} from "lucide-react";
import {
  Card,
  CardHeader,
  CardTitle,
  CardDescription,
  CardContent,
  CardFooter,
} from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Skeleton } from "@/components/ui/skeleton";
import { PageTitle, Choice, TextField } from "@/components/shared";
import { HelpTip } from "@/components/help";
import { usePanelRoute } from "@/lib/use-panel-route";
import { api } from "@/lib/api";
import type { Inventory, Metrics, TrafficArchive } from "@/lib/api";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { LocaleContext, useT } from "@/lib/i18n";
import { engineName, trafficBytes, number } from "@/lib/format";
import { archiveSamples } from "./history";
import { UsageList } from "./UsageList";
import { TrafficActions } from "./TrafficActions";
import { cycleUsage, quotaUsage, csvCell } from "./accounting";
const TrafficChart = lazy(() => import("./TrafficChart"));

export function TrafficWorkspace({
  inventory,
  metrics,
  busy,
  refresh,
  run,
  view,
  onDetails,
}: {
  inventory: Inventory;
  view: "list" | "details";
  onDetails: () => void;
  metrics?: Metrics;
  busy: boolean;
  refresh: () => Promise<void>;
  run: (r: unknown) => Promise<void>;
}) {
  const t = useT(),
    locale = useContext(LocaleContext);
  const [query, setQuery] = useState(""),
    [engine, setEngine] = useState("all"),
    [chosen, setChosen] = useState("");
  const { params, updateParams } = usePanelRoute();
  const chosenID = params.get("resource") || chosen;
  const resources = [
    ...inventory.connections.map((c) => ({
      id: c.id,
      name: c.name,
      engine: c.engine,
      port: c.ports,
    })),
    ...inventory.resources
      .filter((r) => r.engine === "gre" || (r.role === "entrance" && r.port))
      .map((r) => ({
        id: r.id,
        name: r.name,
        engine: r.engine,
        port: r.port ? String(r.port) : r.interface || "",
      })),
  ];
  const knownIDs = [
    ...new Set([
      ...resources.map((r) => r.id),
      ...Object.keys(metrics?.counters || {}),
      ...Object.keys(metrics?.policies || {}),
    ]),
  ];
  const rows = knownIDs.map((id) => ({
    id,
    resource: resources.find((r) => r.id === id),
    counter: metrics?.counters[id],
    policy: metrics?.policies?.[id],
  }));
  const filtered = rows.filter(
    (r) =>
      (engine === "all" || r.resource?.engine === engine) &&
      `${r.resource?.name || r.id} ${r.resource?.port || ""} ${r.policy?.label || ""}`
        .toLocaleLowerCase()
        .includes(query.toLocaleLowerCase()),
  );
  const selected = filtered.find((r) => r.id === chosenID) || filtered[0];
  const c = selected?.counter,
    p = selected?.policy;
  const usage = c ? cycleUsage(c) : { received: 0, sent: 0 },
    quota = quotaUsage(c, p);
  const connection = inventory.connections.find((r) => r.id === selected?.id);
  const [archive, setArchive] = useState<TrafficArchive>();
  const [archiveError, setArchiveError] = useState("");
  const archiveID = selected?.id,
    lastUpdate = c?.updated,
    archiveRevision = metrics?.revision;
  useEffect(() => {
    if (!archiveID || view !== "details") return;
    let live = true;
    api<TrafficArchive>(`metrics/history?id=${encodeURIComponent(archiveID)}`)
      .then((v) => {
        if (live) {
          setArchive(v);
          setArchiveError("");
        }
      })
      .catch((e) => {
        if (live) setArchiveError(String(e));
      });
    return () => {
      live = false;
    };
  }, [archiveID, lastUpdate, archiveRevision, view]);
  const currentArchive = archive?.id === selected?.id ? archive : undefined;
  const date = (s?: string) =>
    s && Date.parse(s) > 0
      ? new Date(s).toLocaleString(
          locale === "fa" ? "fa-IR-u-nu-latn" : "en-US",
        )
      : "—";
  const points = archiveSamples(currentArchive, c?.cycle_start);
  function exportCSV() {
    const data = [
      [
        "ID",
        "Name",
        "Engine",
        "Port",
        "Customer",
        "Received bytes (cycle)",
        "Sent bytes (cycle)",
        "Quota bytes",
        "Quota direction",
        "Cycle start",
        "Last sample",
      ],
      ...filtered.map((r) => {
        const v = r.counter
          ? cycleUsage(r.counter)
          : { received: "", sent: "" };
        return [
          r.id,
          r.resource?.name || "",
          r.resource?.engine || "archived",
          r.resource?.port || "",
          r.policy?.label || "",
          v.received,
          v.sent,
          r.policy?.limit || 0,
          r.policy?.direction || "total",
          r.counter?.cycle_start || metrics?.since || "",
          r.counter?.updated || "",
        ];
      }),
    ]
      .map((row) => row.map(csvCell).join(","))
      .join("\r\n");
    const url = URL.createObjectURL(
      new Blob(["\uFEFF", data], { type: "text/csv;charset=utf-8" }),
    );
    const a = document.createElement("a");
    a.href = url;
    a.download = "tunnel-traffic.csv";
    a.click();
    URL.revokeObjectURL(url);
  }
  return (
    <section
      className="flex flex-col gap-5"
      aria-label={t("usageByConnection")}
    >
      {view !== "list" && (
        <PageTitle
          heading="h2"
          title={t("usageByConnection")}
          description={t("ledgerDescription")}
          action={
            <Button
              variant="outline"
              onClick={exportCSV}
              disabled={!rows.length}
            >
              <Download data-icon="inline-start" />
              {t("exportCSV")}
            </Button>
          }
        />
      )}
      {archiveError && (
        <Alert variant="destructive">
          <AlertDescription>{archiveError}</AlertDescription>
        </Alert>
      )}
      {view === "list" ? (
        <UsageList
          rows={filtered}
          onExport={exportCSV}
          inventory={inventory}
          metrics={metrics}
          busy={busy}
          run={run}
          refresh={refresh}
          query={query}
          onQuery={setQuery}
          engine={engine}
          onEngine={setEngine}
          onDetails={(id) => {
            setChosen(id);
            updateParams({ resource: id });
            onDetails();
          }}
        />
      ) : (
        <div className="grid items-start gap-5 xl:grid-cols-[minmax(17rem,0.8fr)_minmax(0,1.7fr)]">
          <Card className="hidden min-w-0 xl:flex">
            <CardHeader>
              <CardTitle>{t("trackedResources")}</CardTitle>
              <CardDescription>{t("localAccounting")}</CardDescription>
            </CardHeader>
            <CardContent className="flex flex-col gap-4">
              <TextField
                id="usage-search"
                label={t("search")}
                placeholder={t("usageSearch")}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
              />
              <Choice
                id="usage-engine"
                label={t("method")}
                value={engine}
                onChange={setEngine}
                choices={[
                  { value: "all", label: t("allMethods") },
                  ...Array.from(new Set(resources.map((r) => r.engine))).map(
                    (e) => ({ value: e, label: engineName(e) }),
                  ),
                ]}
              />
              <div
                className="max-h-96 flex flex-col gap-2 overflow-y-auto p-1"
                role="group"
                aria-label={t("trackedResources")}
              >
                {filtered.length ? (
                  filtered.map((r) => {
                    const q = quotaUsage(r.counter, r.policy);
                    return (
                      <button
                        key={r.id}
                        type="button"
                        aria-pressed={selected?.id === r.id}
                        onClick={() => {
                          setChosen(r.id);
                          updateParams({ resource: r.id });
                        }}
                        className={`flex w-full items-center justify-between gap-3 rounded-xl border p-3 text-start transition-colors hover:bg-accent ${selected?.id === r.id ? "border-primary bg-accent" : "border-border"}`}
                      >
                        <span className="min-w-0">
                          <span className="block truncate font-medium">
                            {r.resource?.name || r.id}
                          </span>
                          <span className="mt-1 block truncate text-xs text-muted-foreground">
                            {r.policy?.label ||
                              engineName(r.resource?.engine || "archived")}{" "}
                            · <bdi>{r.resource?.port}</bdi>
                          </span>
                        </span>
                        {q.reached ? (
                          <Badge
                            variant="outline"
                            className="border-destructive/40"
                          >
                            {t("quotaReached")}
                          </Badge>
                        ) : (
                          <span className="shrink-0 text-xs tabular-nums">
                            <bdi>{trafficBytes(q.used, locale)}</bdi>
                          </span>
                        )}
                      </button>
                    );
                  })
                ) : (
                  <p className="py-8 text-center text-sm text-muted-foreground">
                    {t("noTrackableResources")}
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
          <Card className="min-w-0 xl:hidden">
            <CardContent>
              <Choice
                id="traffic-resource-mobile"
                label={t("trackedResource")}
                value={selected?.id || ""}
                onChange={(id) => {
                  setChosen(id);
                  updateParams({ resource: id });
                  setQuery("");
                  setEngine("all");
                }}
                choices={rows.map((r) => ({
                  value: r.id,
                  label: `${r.resource?.name || r.id} · ${r.resource?.port || ""}${r.policy?.label ? " · " + r.policy.label : ""}`,
                }))}
              />
            </CardContent>
          </Card>
          {selected ? (
            <div className="min-w-0 flex flex-col gap-5">
              <Card className="min-w-0">
                <CardHeader>
                  <div className="flex flex-wrap items-start justify-between gap-3">
                    <div className="min-w-0 flex flex-col gap-1">
                      <CardTitle className="break-words">
                        {selected.resource?.name || selected.id}
                      </CardTitle>
                      <CardDescription>
                        {p?.label || t("unassignedCustomer")}
                      </CardDescription>
                    </div>
                    <Badge variant="outline">
                      <bdi>
                        {selected.resource
                          ? engineName(selected.resource.engine)
                          : t("removedResource")}
                      </bdi>
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent className="flex flex-col gap-6">
                  <div className="grid grid-cols-3 gap-2 sm:gap-3">
                    {[
                      ["received", usage.received, ArrowDownLeft],
                      ["sent", usage.sent, ArrowUpRight],
                      ["total", usage.received + usage.sent, SlidersHorizontal],
                    ].map(([key, value, Icon]) => {
                      const Glyph = Icon as typeof ArrowDownLeft;
                      return (
                        <div
                          className="rounded-xl border bg-muted/30 p-3 sm:p-4"
                          key={String(key)}
                        >
                          <div className="mb-3 flex items-center justify-between gap-2 text-xs text-muted-foreground">
                            <span>{t(String(key))}</span>
                            <Glyph className="size-4" />
                          </div>
                          <p className="text-base font-semibold tracking-tight tabular-nums sm:text-2xl">
                            <bdi>
                              {c ? trafficBytes(Number(value), locale) : "—"}
                            </bdi>
                          </p>
                        </div>
                      );
                    })}
                  </div>
                  <div className="flex flex-col gap-3 rounded-xl border p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="flex items-center gap-1 text-sm font-medium">
                        {t("cycleQuota")}
                        <HelpTip>{t("quotaHelp")}</HelpTip>
                      </span>
                      <Badge
                        variant="outline"
                        className={
                          quota.reached ? "border-destructive/40" : undefined
                        }
                      >
                        {t(
                          quota.reached
                            ? "quotaReached"
                            : p?.limit
                              ? "withinQuota"
                              : "noQuota",
                        )}
                      </Badge>
                    </div>
                    {Boolean(p?.limit) && (
                      <>
                        <div
                          className="h-2 overflow-hidden rounded-full bg-muted"
                          role="progressbar"
                          aria-label={t("cycleQuota")}
                          aria-valuemin={0}
                          aria-valuemax={100}
                          aria-valuenow={Math.round(quota.percent)}
                        >
                          <div
                            className="h-full rounded-full bg-primary"
                            style={{ width: `${quota.percent}%` }}
                          />
                        </div>
                        <p className="text-sm tabular-nums">
                          <bdi>
                            {trafficBytes(quota.used, locale)} /{" "}
                            {trafficBytes(p!.limit, locale)}
                          </bdi>{" "}
                          · {t(p!.direction)}
                        </p>
                      </>
                    )}
                    <p className="text-xs leading-6 text-muted-foreground">
                      {t("advisoryQuota")}
                    </p>
                  </div>
                  <dl className="grid gap-4 text-sm sm:grid-cols-2">
                    {[
                      ["cycleStarted", date(c?.cycle_start || metrics?.since)],
                      ["lastSample", date(c?.updated)],
                      [
                        "lifetimeUsage",
                        c ? trafficBytes(c.received + c.sent, locale) : "—",
                      ],
                      [
                        "counterSource",
                        c?.source === "nftables"
                          ? t("nftAccounting")
                          : c?.source || t("waitingSample"),
                      ],
                    ].map(([label, value]) => (
                      <div key={label} className="flex flex-col gap-1">
                        <dt className="text-xs text-muted-foreground">
                          {t(label)}
                        </dt>
                        <dd className="break-words tabular-nums">
                          <bdi dir={label === "counterSource" ? "auto" : "ltr"}>
                            {value}
                          </bdi>
                        </dd>
                      </div>
                    ))}
                  </dl>
                </CardContent>
                <TrafficActions
                  key={selected.id}
                  id={selected.id}
                  name={selected.resource?.name || selected.id}
                  connection={connection}
                  removed={!selected.resource}
                  policy={p}
                  revision={metrics?.revision}
                  disabled={busy}
                  run={run}
                  refresh={refresh}
                />
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>{t("trafficTrend")}</CardTitle>
                  <CardDescription>
                    {t(
                      metrics?.settings.retention_hours
                        ? "retainedChartHelp"
                        : "historyOffHelp",
                    )}
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {points.length >= 2 ? (
                    <Suspense fallback={<Skeleton className="h-64 w-full" />}>
                      <TrafficChart samples={points} />
                    </Suspense>
                  ) : (
                    <p className="py-12 text-center text-sm text-muted-foreground">
                      {t("chartWaitingHelp")}
                    </p>
                  )}
                </CardContent>
                <CardFooter className="text-xs text-muted-foreground">
                  {number(points.length, locale)} / {number(288, locale)} ·{" "}
                  {t("retainedSamples")}
                </CardFooter>
              </Card>
              {!!currentArchive?.cycles?.length && (
                <Card>
                  <CardHeader>
                    <CardTitle>{t("previousCycles")}</CardTitle>
                  </CardHeader>
                  <CardContent className="flex flex-col gap-3">
                    {currentArchive.cycles
                      .slice()
                      .reverse()
                      .map((cycle) => (
                        <div
                          key={cycle.end}
                          className="flex flex-wrap justify-between gap-2 border-b pb-3 text-sm"
                        >
                          <span className="text-muted-foreground">
                            {date(cycle.end)}
                            {cycle.label && (
                              <span className="mt-1 block">{cycle.label}</span>
                            )}
                          </span>
                          <bdi>
                            {trafficBytes(cycle.received + cycle.sent, locale)}
                          </bdi>
                        </div>
                      ))}
                  </CardContent>
                </Card>
              )}
            </div>
          ) : (
            <Card>
              <CardContent className="py-16 text-center text-sm text-muted-foreground">
                {t("noTrackableResources")}
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </section>
  );
}
