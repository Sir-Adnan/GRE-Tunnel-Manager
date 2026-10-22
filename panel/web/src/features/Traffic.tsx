import { lazy, Suspense, useContext } from "react";
import {
  Activity,
  ArrowDownLeft,
  ArrowUpRight,
  RefreshCw,
  Settings2,
} from "lucide-react";
import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
  CardHeader,
  CardTitle,
} from "@/components/ui/card";
import { Switch } from "@/components/ui/switch";
import { Checkbox } from "@/components/ui/checkbox";
import {
  Field,
  FieldContent,
  FieldGroup,
  FieldLabel,
  FieldSet,
  FieldLegend,
} from "@/components/ui/field";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Empty,
  EmptyHeader,
  EmptyTitle,
  EmptyDescription,
  EmptyMedia,
} from "@/components/ui/empty";
import { Skeleton } from "@/components/ui/skeleton";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageTitle, TextField, Choice } from "@/components/shared";
import { HelpTip } from "@/components/help";
import type { Inventory } from "@/lib/api";
import { engineName, number, trafficBytes } from "@/lib/format";
import { LocaleContext, useT } from "@/lib/i18n";
import { useTraffic } from "./traffic/useTraffic";

const TrafficChart = lazy(() => import("./traffic/TrafficChart"));

export function Traffic({
  inventory,
  run,
}: {
  inventory: Inventory;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const {
    metrics,
    enabled,
    setEnabled,
    interval,
    setInterval,
    ids,
    setIDs,
    all,
    setAll,
    error,
    busy,
    loading,
    setChartID,
    dirty,
    invalid,
    refresh,
    save,
    counters,
    selectedID,
    samples,
  } = useTraffic(run);
  const resources = [
    ...inventory.connections.map((c) => ({
      id: c.id,
      name: c.name,
      engine: c.engine,
    })),
    ...inventory.resources
      .filter(
        (r) => r.engine === "gre" || (r.role === "entrance" && Boolean(r.port)),
      )
      .map((r) => ({ id: r.id, name: r.name, engine: r.engine })),
  ];
  return (
    <div className="page-stack">
      <PageTitle
        title={t("traffic")}
        description={t("trafficDesc")}
        action={
          <Button
            variant="outline"
            disabled={loading || busy}
            onClick={() => void refresh()}
          >
            <RefreshCw
              data-icon="inline-start"
              className={loading ? "animate-spin" : undefined}
            />
            {t("refresh")}
          </Button>
        }
      />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <Card>
        <CardHeader>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <CardTitle className="flex items-center gap-2">
              <Settings2 className="size-4" />
              {t("collectionSettings")}
            </CardTitle>
            <Badge variant="outline">
              {t(metrics?.settings.enabled ? "collecting" : "collectionPaused")}
            </Badge>
          </div>
          <CardDescription>{t("collectionSummary")}</CardDescription>
        </CardHeader>
        <CardContent>
          <form id="metrics-form" onSubmit={save}>
            <FieldGroup>
              <div className="grid gap-6 md:grid-cols-2">
                <FieldGroup>
                  <Field orientation="horizontal">
                    <FieldContent>
                      <div className="flex items-center gap-1">
                        <FieldLabel htmlFor="metrics-enabled">
                          {t("collect")}
                        </FieldLabel>
                        <HelpTip>{t("collectHelp")}</HelpTip>
                      </div>
                      <p
                        className="text-xs leading-6 text-muted-foreground"
                        role="status"
                      >
                        {t(
                          enabled ? "collectionOnDraft" : "collectionOffDraft",
                        )}
                      </p>
                    </FieldContent>
                    <Switch
                      id="metrics-enabled"
                      checked={enabled}
                      disabled={!metrics || busy}
                      onCheckedChange={setEnabled}
                    />
                  </Field>
                  <Field orientation="horizontal">
                    <FieldLabel htmlFor="track-all">{t("trackAll")}</FieldLabel>
                    <Switch
                      id="track-all"
                      checked={all}
                      disabled={!metrics || busy}
                      onCheckedChange={setAll}
                    />
                  </Field>
                </FieldGroup>
                <TextField
                  id="metrics-interval"
                  label={t("interval")}
                  help={t("intervalHelp")}
                  type="number"
                  min={15}
                  max={3600}
                  value={interval}
                  disabled={!metrics || busy}
                  onChange={(event) => setInterval(Number(event.target.value))}
                  required
                />
              </div>
              {!all && (
                <FieldSet>
                  <FieldLegend>{t("trackedResources")}</FieldLegend>
                  <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
                    {resources.map((r) => (
                      <Field
                        className="rounded-lg border p-3"
                        orientation="horizontal"
                        key={r.id}
                      >
                        <Checkbox
                          id={`metric-${r.id}`}
                          checked={ids.includes(r.id)}
                          disabled={busy}
                          onCheckedChange={(checked) =>
                            setIDs((current) =>
                              checked === true
                                ? [...new Set([...current, r.id])]
                                : current.filter((id) => id !== r.id),
                            )
                          }
                        />
                        <FieldLabel
                          className="min-w-0 flex-1"
                          htmlFor={`metric-${r.id}`}
                        >
                          <span className="flex min-w-0 flex-col gap-1">
                            <span className="truncate">{r.name}</span>
                            <span className="text-xs text-muted-foreground">
                              <bdi>{engineName(r.engine)}</bdi>
                            </span>
                          </span>
                        </FieldLabel>
                      </Field>
                    ))}
                  </div>
                  {!resources.length && (
                    <p className="text-sm text-muted-foreground">
                      {t("noTrackableResources")}
                    </p>
                  )}
                  {enabled && !ids.length && (
                    <p role="status" className="text-sm text-muted-foreground">
                      {t("selectResourceFirst")}
                    </p>
                  )}
                </FieldSet>
              )}
            </FieldGroup>
          </form>
        </CardContent>
        <CardFooter className="flex flex-wrap justify-between gap-3">
          <p className="text-xs text-muted-foreground" role="status">
            {t(dirty ? "unsavedChanges" : "settingsApplied")}
          </p>
          <Button
            type="submit"
            form="metrics-form"
            disabled={!metrics || busy || invalid || !dirty}
          >
            {t(busy ? "working" : "save")}
          </Button>
        </CardFooter>
      </Card>
      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <CardTitle>{t("usageByConnection")}</CardTitle>
            <HelpTip>{t("metricsNote")}</HelpTip>
          </div>
          <CardDescription>{t("trafficTableHelp")}</CardDescription>
        </CardHeader>
        <CardContent>
          {metrics?.error && (
            <Alert variant="destructive" className="mb-4">
              <AlertDescription>{metrics.error}</AlertDescription>
            </Alert>
          )}
          {!metrics && !error ? (
            <Skeleton className="h-36 w-full" />
          ) : !counters.length ? (
            <Empty>
              <EmptyHeader>
                <EmptyMedia variant="icon">
                  <Activity />
                </EmptyMedia>
                <EmptyTitle>
                  {t(
                    metrics?.settings.enabled
                      ? "waitingSample"
                      : "collectionPaused",
                  )}
                </EmptyTitle>
                <EmptyDescription>
                  {t(
                    metrics?.settings.enabled
                      ? "waitingSampleHelp"
                      : "noTraffic",
                  )}
                </EmptyDescription>
              </EmptyHeader>
            </Empty>
          ) : (
            <div className="table-frame">
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>{t("name")}</TableHead>
                    <TableHead>{t("received")}</TableHead>
                    <TableHead>{t("sent")}</TableHead>
                    <TableHead>{t("total")}</TableHead>
                    <TableHead>{t("lastSample")}</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {counters.map(([id, counter]) => {
                    const resource = resources.find((r) => r.id === id);
                    return (
                      <TableRow key={id}>
                        <TableCell>
                          <div className="flex flex-col gap-1">
                            <span className="font-medium">
                              {resource?.name || id}
                            </span>
                            <div className="flex items-center gap-1 text-xs text-muted-foreground">
                              <bdi>
                                {resource
                                  ? engineName(resource.engine)
                                  : t("removedResource")}
                              </bdi>
                              <HelpTip
                                label={`${t("counterSource")} · ${resource?.name || id}`}
                              >{`${t("connectionID")}: ${id}. ${t("counterSource")}: ${counter.source === "nftables" ? t("nftAccounting") : counter.source}. ${t("counterSourceHelp")}`}</HelpTip>
                            </div>
                          </div>
                        </TableCell>
                        <TableCell>
                          <span className="inline-flex items-center gap-1.5 tabular-nums">
                            <ArrowDownLeft className="size-3.5" />
                            <bdi>{trafficBytes(counter.received, locale)}</bdi>
                          </span>
                        </TableCell>
                        <TableCell>
                          <span className="inline-flex items-center gap-1.5 tabular-nums">
                            <ArrowUpRight className="size-3.5" />
                            <bdi>{trafficBytes(counter.sent, locale)}</bdi>
                          </span>
                        </TableCell>
                        <TableCell className="font-medium tabular-nums">
                          <bdi>
                            {trafficBytes(
                              counter.received + counter.sent,
                              locale,
                            )}
                          </bdi>
                        </TableCell>
                        <TableCell className="text-xs text-muted-foreground">
                          {Date.parse(counter.updated) > 0
                            ? new Date(counter.updated).toLocaleString(
                                locale === "fa" ? "fa-IR" : "en-US",
                              )
                            : "—"}
                        </TableCell>
                      </TableRow>
                    );
                  })}
                </TableBody>
              </Table>
            </div>
          )}
        </CardContent>
        <CardFooter>
          <p className="text-xs leading-6 text-muted-foreground">
            {t("separateTotals")}
          </p>
        </CardFooter>
      </Card>
      <Card>
        <CardHeader>
          <CardTitle>{t("trafficTrend")}</CardTitle>
          <CardDescription>{t("sessionChartHelp")}</CardDescription>
        </CardHeader>
        <CardContent>
          {counters.length > 0 && (
            <div className="mb-5 max-w-sm">
              <Choice
                id="chart-resource"
                label={t("trackedResource")}
                value={selectedID}
                onChange={setChartID}
                choices={counters.map(([id]) => ({
                  value: id,
                  label: resources.find((r) => r.id === id)?.name || id,
                }))}
              />
            </div>
          )}
          {samples.length >= 2 ? (
            <Suspense fallback={<Skeleton className="h-64 w-full" />}>
              <TrafficChart samples={samples} />
            </Suspense>
          ) : (
            <Empty>
              <EmptyHeader>
                <EmptyTitle>{t("chartWaiting")}</EmptyTitle>
                <EmptyDescription>{t("chartWaitingHelp")}</EmptyDescription>
              </EmptyHeader>
            </Empty>
          )}
        </CardContent>
        <CardFooter>
          <span className="text-xs text-muted-foreground">
            {number(samples.length, locale)} / {number(60, locale)} ·{" "}
            {t("sessionSamples")}
          </span>
        </CardFooter>
      </Card>
    </div>
  );
}
