import { useEffect, useState } from "react";
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
import { Field, FieldGroup, FieldLabel } from "@/components/ui/field";
import { Button } from "@/components/ui/button";
import { Alert, AlertDescription } from "@/components/ui/alert";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { PageTitle, TextField } from "@/components/shared";
import { api, bytes } from "@/lib/api";
import type { Inventory, Metrics } from "@/lib/api";
import { useT } from "@/lib/i18n";

export function Traffic({
  inventory,
  run,
}: {
  inventory: Inventory;
  run: (request: unknown) => Promise<void>;
}) {
  const t = useT();
  const [metrics, setMetrics] = useState<Metrics>();
  const [enabled, setEnabled] = useState(false);
  const [interval, setInterval] = useState(60);
  const [ids, setIDs] = useState<string[]>([]);
  const [all, setAll] = useState(true);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);
  useEffect(() => {
    let live = true;
    api<Metrics>("metrics")
      .then((value) => {
        if (!live) return;
        setMetrics(value);
        setEnabled(value.settings.enabled);
        setInterval(value.settings.interval);
        setIDs(value.settings.ids || []);
        setAll(!value.settings.ids?.length);
      })
      .catch((error) => live && setError(String(error)));
    return () => {
      live = false;
    };
  }, []);
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
  async function save() {
    setBusy(true);
    try {
      await run({
        action: "metrics-configure",
        metrics: { enabled, interval, ids: all ? [] : ids },
      });
      setMetrics(await api<Metrics>("metrics"));
    } catch (error) {
      setError(String(error));
    } finally {
      setBusy(false);
    }
  }
  return (
    <div className="page-stack">
      <PageTitle title={t("traffic")} description={t("trafficDesc")} />
      {error && (
        <Alert>
          <AlertDescription>{error}</AlertDescription>
        </Alert>
      )}
      <div className="grid gap-5 lg:grid-cols-[1fr_1.6fr]">
        <Card>
          <CardHeader>
            <CardTitle>{t("collect")}</CardTitle>
            <CardDescription>{t("collectHelp")}</CardDescription>
          </CardHeader>
          <CardContent>
            <FieldGroup>
              <Field orientation="horizontal">
                <FieldLabel htmlFor="metrics-enabled">
                  {t("collect")}
                </FieldLabel>
                <Switch
                  id="metrics-enabled"
                  checked={enabled}
                  onCheckedChange={setEnabled}
                />
              </Field>
              <TextField
                id="metrics-interval"
                label={t("interval")}
                type="number"
                min={15}
                max={3600}
                value={interval}
                onChange={(event) => setInterval(Number(event.target.value))}
              />
              <Field orientation="horizontal">
                <FieldLabel htmlFor="track-all">{t("trackAll")}</FieldLabel>
                <Switch id="track-all" checked={all} onCheckedChange={setAll} />
              </Field>
              {!all &&
                resources.map((r) => (
                  <Field orientation="horizontal" key={r.id}>
                    <Checkbox
                      id={`metric-${r.id}`}
                      checked={ids.includes(r.id)}
                      onCheckedChange={(checked) =>
                        setIDs(
                          checked
                            ? [...ids, r.id]
                            : ids.filter((id) => id !== r.id),
                        )
                      }
                    />
                    <FieldLabel htmlFor={`metric-${r.id}`}>{r.name}</FieldLabel>
                  </Field>
                ))}
            </FieldGroup>
          </CardContent>
          <CardFooter>
            <Button
              onClick={save}
              disabled={busy || (enabled && !all && ids.length === 0)}
            >
              {t(busy ? "working" : "save")}
            </Button>
          </CardFooter>
        </Card>
        <Card>
          <CardHeader>
            <CardTitle>{t("traffic")}</CardTitle>
            <CardDescription>{t("metricsNote")}</CardDescription>
          </CardHeader>
          <CardContent>
            {metrics?.error && (
              <Alert>
                <AlertDescription>{metrics.error}</AlertDescription>
              </Alert>
            )}
            {!metrics?.settings.enabled && (
              <p className="py-12 text-center text-sm text-muted-foreground">
                {t("noTraffic")}
              </p>
            )}
            <Table>
              <TableHeader>
                <TableRow>
                  <TableHead>{t("name")}</TableHead>
                  <TableHead>{t("received")}</TableHead>
                  <TableHead>{t("sent")}</TableHead>
                  <TableHead>{t("total")}</TableHead>
                </TableRow>
              </TableHeader>
              <TableBody>
                {Object.entries(metrics?.counters || {}).map(
                  ([id, counter]) => (
                    <TableRow key={id}>
                      <TableCell>
                        <div className="flex flex-col gap-1">
                          <span>
                            {resources.find((r) => r.id === id)?.name || id}
                          </span>
                          <span
                            className="text-xs text-muted-foreground"
                            dir="ltr"
                          >
                            {id} · {counter.source}
                          </span>
                        </div>
                      </TableCell>
                      <TableCell>
                        <code>{bytes(counter.received)}</code>
                      </TableCell>
                      <TableCell>
                        <code>{bytes(counter.sent)}</code>
                      </TableCell>
                      <TableCell>
                        <code>{bytes(counter.received + counter.sent)}</code>
                      </TableCell>
                    </TableRow>
                  ),
                )}
              </TableBody>
            </Table>
          </CardContent>
          <CardFooter>
            <Button
              variant="outline"
              onClick={() =>
                api<Metrics>("metrics")
                  .then(setMetrics)
                  .catch((error) => setError(String(error)))
              }
            >
              {t("refresh")}
            </Button>
          </CardFooter>
        </Card>
      </div>
    </div>
  );
}
