import { Tabs, TabsList, TabsTrigger, TabsContent } from "@/components/ui/tabs";
import { TrafficWorkspace } from "./traffic/TrafficWorkspace";
import { RefreshCw, Settings2 } from "lucide-react";
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
import { PageTitle, TextField, Choice } from "@/components/shared";
import { HelpTip } from "@/components/help";
import type { Inventory } from "@/lib/api";
import { engineName } from "@/lib/format";
import { useContext } from "react";
import { LocaleContext, useT } from "@/lib/i18n";
import { usePanelRoute } from "@/lib/use-panel-route";
import { useTraffic } from "./traffic/useTraffic";

export function Traffic({
  inventory,
  run,
}: {
  inventory: Inventory;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const locale = useContext(LocaleContext);
  const { params, updateParams } = usePanelRoute();
  const section = ["details", "collection"].includes(params.get("tab") || "")
    ? params.get("tab")!
    : "usage";
  const setSection = (tab: string) =>
    updateParams({ tab: tab === "usage" ? "" : tab });
  const {
    metrics,
    enabled,
    setEnabled,
    interval,
    setInterval,
    retention,
    setRetention,
    ids,
    setIDs,
    all,
    setAll,
    error,
    busy,
    loading,
    dirty,
    invalid,
    refresh,
    save,
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
          <div className="flex flex-wrap items-center gap-3">
            <Badge variant="outline">
              {t(metrics?.settings.enabled ? "collecting" : "collectionPaused")}
            </Badge>
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
          </div>
        }
      />
      {error && (
        <Alert variant="destructive">
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      {metrics?.error && (
        <Alert variant="destructive">
          <AlertDescription>{metrics.error}</AlertDescription>
        </Alert>
      )}
      <Tabs
        dir={locale === "fa" ? "rtl" : "ltr"}
        value={section}
        onValueChange={setSection}
        className="gap-5"
      >
        <TabsList
          className="h-auto min-h-10 w-full flex-wrap sm:w-fit"
          aria-label={t("trafficSections")}
        >
          <TabsTrigger value="usage">{t("allUsage")}</TabsTrigger>
          <TabsTrigger value="details">{t("usageDetails")}</TabsTrigger>
          <TabsTrigger value="collection">
            {t("collectionSettings")}
            {dirty ? " *" : ""}
          </TabsTrigger>
        </TabsList>
        {section !== "collection" && (
          <TabsContent value={section}>
            {" "}
            <TrafficWorkspace
              inventory={inventory}
              view={section === "details" ? "details" : "list"}
              onDetails={() => setSection("details")}
              metrics={metrics}
              busy={busy}
              refresh={refresh}
              run={run}
            />
          </TabsContent>
        )}
        <TabsContent value="collection">
          {" "}
          <Card>
            <CardHeader>
              <div className="flex flex-wrap items-center justify-between gap-3">
                <CardTitle className="flex items-center gap-2">
                  <Settings2 className="size-4" />
                  {t("collectionSettings")}
                </CardTitle>
                <Badge variant="outline">
                  {t(
                    metrics?.settings.enabled
                      ? "collecting"
                      : "collectionPaused",
                  )}
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
                              enabled
                                ? "collectionOnDraft"
                                : "collectionOffDraft",
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
                        <FieldLabel htmlFor="track-all">
                          {t("trackAll")}
                        </FieldLabel>
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
                      onChange={(event) =>
                        setInterval(Number(event.target.value))
                      }
                      required
                    />
                  </div>
                  <Choice
                    id="traffic-retention"
                    label={t("retention")}
                    value={String(retention)}
                    onChange={(v) => setRetention(Number(v))}
                    choices={[
                      { value: "0", label: t("historyOff") },
                      { value: "24", label: t("historyDay") },
                      { value: "168", label: t("historyWeek") },
                      { value: "720", label: t("historyMonth") },
                    ]}
                  />
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
                        <p
                          role="status"
                          className="text-sm text-muted-foreground"
                        >
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
        </TabsContent>
      </Tabs>
    </div>
  );
}
